# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.1] — 2026-07-24

### Fixed

- **AG-NET-02: finding accuracy.** The verdict was right; the wording was not.
  Egress from the site's *own* subdomain was reported as a "third-party CDN"
  (host-exact comparison), and `<iframe>`/`<embed>`/`<object>` document embeds
  were lumped in with in-origin subresources. A cross-origin URL under the same
  registrable domain (eTLD+1, via `golang.org/x/net/publicsuffix`) is now
  labelled "cross-origin same-site (own registrable domain)", and browsing-context
  embeds are called "document embeds", not subresources. No verdict changes —
  cross-origin egress still fails at L0; only the finding text and remedy differ.
  This matters because the text ships in reports and a single false statement
  discredits the whole report.

## [1.2.0] — 2026-07-06

### Fixed (adversarial review pass — AG-NET-* + AG-SUP-01)

- **AG-NET-01:** a policy that scoped some directives but left the rest unset
  (no `default-src` to fall back to) used to PASS despite the browser's
  wide-open initial value for missing fetch-directives. Now flagged with
  evidence naming each unset directive.
- **AG-NET-02: full rewrite.** The prior implementation substring-matched
  seven hardcoded CDN hostnames against the raw HTML body — false-positive on
  prose ("do not use cdn.jsdelivr.net") and false-negative on every real CDN
  not in the list (`ajax.googleapis.com`, `code.jquery.com`, CNAMEs, S3/R2
  buckets, …). Replaced with an HTML-aware enumerator of every
  subresource-fetching element (`<script src>`, `<link rel=stylesheet|
  modulepreload|preload|prefetch|icon>`, `<img src>`/`<img srcset>`,
  `<iframe|embed|video|audio|source|track src>`, `<object data>`). Any
  cross-origin URL fails at L0; at L1+ a new `allow.subresources` allow-list
  scopes exemptions by exact host.
- **AG-NET-03:** `worker-src` now walks the real CSP L3 fallback chain
  (worker-src → child-src → script-src → default-src) rather than
  short-circuiting to `default-src`. A permissive `script-src` that used to
  hide behind `default-src 'none'` is now caught.
- **AG-NET-06:** also parses the `Link` HTTP header (RFC 8288) for
  `preconnect`/`dns-prefetch` — a server could prime any origin without
  touching the HTML and silently pass. `rel` matching moved from
  `strings.Contains` to token-exact.
- **AG-NET-08:** the previous check treated CSP `report-to` values as URLs,
  but per spec they are GROUP NAMES resolved via the `Reporting-Endpoints`
  and legacy `Report-To` HTTP headers. Endpoints declared through those
  headers were never inspected. Now unions all three sources
  (`report-uri` URLs + `Reporting-Endpoints` structured header +
  `Report-To` JSON header) and judges each against the surface origin.
- **AG-NET-09:** now covers `<form target=_blank action="external">` —
  form submissions leak `window.opener` via the same HTML mechanism as
  `<a>`. `rel` matching is token-exact so `rel="notnoopener"` no longer
  falsely satisfies the check.
- **AG-SUP-01:** required Subresource Integrity to be ENFORCEABLE — not
  merely present. The old check accepted `integrity="sha384-abc"` even
  without a `crossorigin` attribute, but browsers fetch such responses
  opaque (no-CORS) and cannot compute the hash, so SRI is silently
  skipped. Now requires (a) a syntactically valid
  `sha{256,384,512}-<base64>` token and (b) a `crossorigin` attribute.
  Coverage extended to `<link rel=modulepreload>` and
  `<link rel=preload as=script|style>`.

### Added

- `csp.EffectiveWithFallback` — walks the full CSP L3 fallback chain, not
  only `default-src`, for directives that have intermediate fallbacks
  (`worker-src`, `script-src-elem/attr`, `style-src-elem/attr`, `frame-src`).
- `httpx.HostOf` — the previously-unexported `hostOf` is now public so
  sibling packages can reuse the same URL-loose host extraction.
- `manifest.Allow.Subresources` — YAML key `allow.subresources`, additive.
  Consumed by AG-NET-02 at L1+; unused at L0 (strict air-gap).

### Changed

- `csp.Policy.ReportEndpoints()` now returns only `report-uri` targets. The
  prior behavior of also returning `report-to` group names was a footgun
  that caused AG-NET-08's silent bypass; endpoint resolution moved to the
  rules package where the resolving HTTP headers are visible.

## [1.1.0] — 2026-06-16

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

[Unreleased]: https://github.com/fabriziosalmi/agssh/compare/v1.2.1...HEAD
[1.2.1]: https://github.com/fabriziosalmi/agssh/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/fabriziosalmi/agssh/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/fabriziosalmi/agssh/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/fabriziosalmi/agssh/releases/tag/v1.0.0
