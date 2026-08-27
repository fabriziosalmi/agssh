# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.3.3] — 2026-08-27

### Added

- **Every result now discloses a degraded environment.** A missing tool could
  silently disable a whole plane — most importantly, no headless Chrome meant the
  dynamic plane (pre-consent egress, offline proof, egress canary) did not run —
  yet the verdict, score and fix queue came back looking exactly as confident as a
  complete scan; the only trace was one rule's error string, which any status-only
  summary drops (measured: 39.5% via MCP vs 53.5% fully armed, same surface). The
  record and the MCP `ScanResult` now carry an `environment` block (resolved tools
  as booleans — never paths — `degraded`, a one-line reason, and the missing
  tools); the CLI/MCP summary prints a prominent "⚠ Partial scan (degraded
  environment): …" line; and the `agssh_scan` tool description documents the
  Chrome requirement and `AGSSH_CHROME`. A tool no in-scope rule needed does not
  flag degraded. (dogfooding finding RUN-07)
- **Reachability gate: an unreachable surface is now `UNSCANNABLE`, not a low
  score.** Previously, when the live surface could not be fetched at all (NXDOMAIN,
  connection refused, TLS failure, timeout) the runner still produced a full
  record — every static/dynamic rule `INCONCLUSIVE`, a non-zero *possible* score,
  a fix queue, and (with `-badge`) a badge — as if it had inspected a merely weak
  surface. It now short-circuits to a distinct `UNSCANNABLE` record carrying the
  transport cause in one sentence, emits **no** verdict / score / fix queue /
  badge, and exits with the new code **`3`** (distinct from `1` non-conformant).
  This only triggers when a fetch was actually attempted; offline/source-only
  evaluations are unaffected. (dogfooding finding RUN-08)

### Changed

- **The score is now labelled level-relative.** A level change moves rules in or
  out of scope, changing the denominator, so a stricter level can score *lower*
  on the same surface — and nothing in the output said so, while the badge invited
  exactly that comparison. The record now carries `score.scored` (rules in the
  denominator) and the summary prints "Score scope: N rules scored at <level> —
  level-relative, not comparable across levels"; the README says compare medals,
  not numbers. (This is the honesty half of dogfooding finding RUN-06; the
  monotonic-scoring model — never penalising a surface for exceeding its level —
  changes badge numbers and is deferred to a deliberate scoring-model change.)

### Fixed

- **The supply family no longer scores an empty scan as clean.** `AG-SUP-04`
  (secrets) and `AG-SUP-05` (source maps) returned PASS when handed a directory
  with no shipped artifacts — empty, or holding only config/VCS metadata
  (`.airgap.yml`, `.git/`) — while `AG-SUP-06` (vulns) returned INCONCLUSIVE on
  the same input: two rules, one input, opposite postures, and the PASS earned
  real points. A shared precondition now returns **N/A** ("no shipped artifacts
  to scan") for the whole family when the target directory contains no scannable
  (non-hidden) file, keeping the denominator honest and the family coherent. A
  directory with real shipped files still runs every scanner; a genuinely absent
  directory still fails closed to INCONCLUSIVE. (dogfooding finding RUN-04)
- **The fix queue no longer mixes "must fix" with "could not check".** Previously
  `BuildFixQueue` included every non-PASS result — FAIL *and* INCONCLUSIVE —
  severity-ranked together, so an unrun check (missing scanner, unfetched path,
  undeclared DNS zone) appeared as a ranked, actionable fix a surface change
  could never resolve. The output now splits into two: **Fix queue** (FAIL only,
  severity-ranked — things the owner can change) and **Could not assess**
  (INCONCLUSIVE, rule-ID-ordered with the reason, deliberately unranked, since
  severity says nothing about a check that never ran). The JSON record and the
  MCP `ScanResult` carry them as **distinct keys** (`fix_queue` / `unassessed`)
  so a consumer can never flatten them back together. Fail-closed is unchanged —
  an unassessed rule still blocks the gate. (dogfooding finding RUN-09)
- **AG-NET-01's evidence no longer reads as "do what you already do".** The rule
  title ("Self-host every runtime dependency") describes the normative outcome,
  but the runner's checker measures the CSP's *permitted* fetch-directive set —
  what the policy grants, not what the page loads. On a surface that self-hosts
  everything (AG-NET-02 PASS) but carries CSP slack, the CRITICAL fix-queue line
  read as if the operator had failed to self-host. The evidence now says the CSP
  *permits* the third-party origins (the reachable egress set, distinct from
  loaded assets), so the actionable slack is unambiguous. The normative rule
  identity is unchanged. (dogfooding finding RUN-10)
- **Scanner evidence no longer leaks the tool's `--help` chatter.** When
  `osv-scanner` (or `gitleaks`) failed to run — e.g. osv-scanner 2.x printing
  `No package sources found, --help for usage information.` — the runner embedded
  that usage pointer, banners, and ANSI control codes verbatim as the rule's
  INCONCLUSIVE evidence, so a supply-chain result read as if the surface itself
  said "see --help". A shared `toolDiag` sanitizer now strips ANSI/control
  characters and the usage tail and keeps only the real diagnostic line.
  (dogfooding finding RUN-05)
- **Chrome is now discovered on macOS and Windows.** `chromePath` only searched
  `PATH` for Linux binary names, so on a stock macOS/Windows host — where the
  browser lives in an app bundle / Program Files and is never on `PATH` — the
  headless plane silently did not run: the CRITICAL **AG-PRV-02** rule was skipped
  and the score understated by ~8 points, with no indication in the output. The
  resolver now probes the known absolute install locations per OS. (dogfooding
  finding RUN-01)

## [1.3.2] — 2026-08-27

### Fixed

- **`pipeline.enforce_ci_rules` is now wired.** It was declared in the manifest
  and documented ("apply the AG-CI family to .github/workflows") but the engine
  ignored it — the AG-CI family always ran. A web surface would then be marked
  down for its own repo's workflow hygiene. The engine now excludes the AG-CI
  plane when `enforce_ci_rules: false`. (Found by dogfooding the runner against
  live sites whose `.airgap.yml` set it false.)
- **AG-PRV-03 now catches protocol-relative font sources.** The 1.3.1 rewrite
  matched only `https?://`, so a scheme-relative third-party font
  (`<link href="//fonts.gstatic.com…">` or `@font-face { src: url(//cdn/x.woff2) }`)
  slipped through — `httpx.HostOf` reports an empty host for `//host`. The checker
  now normalizes `//` refs before extracting the host, with regression cases.
  (Found by Copilot review of #26.)

## [1.3.1] — 2026-08-27

### Fixed

- **AG-PRV-03 (self-host fonts) no longer false-positives on prose.** The checker
  substring-matched the body for a font-CDN host, so any page whose *text*
  mentioned `fonts.googleapis.com` failed — including the AGSSH standard document,
  which names the host when describing this very rule. It is now HTML-aware: it
  flags a stylesheet/preconnect to a font CDN, a cross-origin
  `<link rel=preload as=font>`, or an `@font-face` src at a cross-origin font
  file — never prose. (Same class of bug as the 1.2.0 AG-NET-02 rewrite.)

### Security

- **No known-vulnerable dependencies.** `golang.org/x/mod` bumped to v0.40.0,
  clearing GO-2026-6179 / GO-2026-6180 (pulled in transitively with the MCP SDK).
- **The runner's own CI Actions are pinned to 40-char SHAs (AG-CI-01)** across
  `ci.yml`, `release.yml` and `retag-major.yml` — agssh now practises the pinning
  it enforces.

Found by dogfooding agssh at Gold against its own repo and rendered standard.

## [1.3.0] — 2026-08-27

### Added

- `retag-major` workflow: the moving `v1` tag now follows the newest release
  automatically (chained after goreleaser + image publish in `release.yml`) or
  via manual dispatch. Fail-closed and fully derived: the target is the newest
  full `vX.Y.Z` tag (anchored filter — prereleases never qualify), the image to
  verify is the `runs.image` pin read from `action.yml` at that tag (a stale or
  foreign pin refuses the move), the pinned ghcr image must exist, the commit
  must be reachable from `main`, and the push is a compare-and-swap
  (`--force-with-lease` on a freshly read remote ref) under a non-canceling
  concurrency group, re-read and verified after pushing; idempotent when `v1`
  already points at the newest release.

- **`agssh-mcp` — the runner as an MCP server.** AGSSH is now exposed over the
  [Model Context Protocol](https://modelcontextprotocol.io) on stdio, so an agent
  can scan a surface without the build/config/parse dance. It reuses the engine
  **in-process** — no shell-out, no temp files — via a new `internal/mcpsrv`
  package. Three read-only tools:
  - `agssh_scan` — evaluate a **live URL**; the manifest is synthesized from the
    arguments (`url`, `profile`, `level`, `kind`, `allow_*`, surface flags). Rules
    that need a source tree report `INCONCLUSIVE`.
  - `agssh_scan_config` — full CLI parity against an existing `.airgap.yml`
    (repo / dist / workflow rules against real paths).
  - `agssh_list_rules` — registry introspection, filterable by family/profile.

  Each scan returns a human summary **and** the full structured conformance
  record. Ships in every release archive; register with
  `claude mcp add agssh -- agssh-mcp` (a repo `.mcp.json` is provided).

- **Self-hosted conformance badge (`-badge out.svg`).** A dependency-free,
  egress-free SVG badge (no web font, no external image, no third-party
  endpoint) that a project serves from its own origin — it cannot violate the
  AG-NET-02 it advertises. It is a deterministic pure function of the record:
  **conformant** shows the earned tier as its metal (`AGSSH · Gold`, a
  reproducible fail-closed claim); **non-conformant** shows the grey *target*
  tier plus the weighted score (`AGSSH · Gold · 41%`) — the medal is the claim,
  the score a development diagnostic. New `internal/badge` package.

### Security

- **`agssh_scan` refuses non-public targets by default (SSRF).** Because the URL
  is caller-supplied, the server no longer fetches or headless-browses
  loopback, link-local (incl. cloud metadata `169.254.169.254`), RFC1918/private,
  unique-local, CGNAT, NAT64 or `0.0.0.0/8` addresses unless the caller sets
  `allow_private_targets`. The block runs at **dial time on the resolved IP**, so
  it also covers redirects and DNS-rebinding; the caller-supplied DNS `resolver`
  is guarded the same way. `agssh_scan_config` keeps CLI trust (operator-authored
  manifest).
- **Wildcard allow-lists are rejected.** A `"*"` in `allow.connect` /
  `allow.subresources` / `allow.embeds` / `allow.storage` would make the
  allow-list disable the very check it scopes (a false PASS at L1+). It is now
  refused at manifest load and by the MCP tools — the standard already requires
  explicit origins, "never '*'".

### Fixed

- **AG-SUP-04: a gitleaks *scan error* is no longer reported as a secret.**
  gitleaks exits `1` both when it finds leaks and on a fatal error (unreadable
  file, malformed `.gitleaks.toml`), so the exit code alone conflated the two.
  The verdict now comes from the JSON report: findings → FAIL, empty → PASS, no
  parseable report on a non-zero exit → INCONCLUSIVE. A tool that could not run
  never manufactures a MUST failure.
- **No working-directory fallback for source-plane scanners.** With no source
  tree (a URL-only scan), `chkNoSecrets`, `chkNoKnownVulns` and `chkSBOM` now
  report `INCONCLUSIVE` instead of a false FAIL, and can no longer let
  `gitleaks` / `osv-scanner` / glob checks silently inspect the process working
  directory. `agssh_scan` anchors the repo/dist/workflow roots to a
  guaranteed-absent absolute path and scrubs it from the emitted evidence.
- **`agssh_scan_config` headline verdict is the AND of every surface**, matching
  the CLI gate — a conformant first surface no longer masks a failing second; the
  detailed fix queue is drawn from the first failing surface, with a per-surface
  roster alongside.

## [1.2.2] — 2026-08-22

### Fixed

- **Generator ↔ hand-written drift.** The standard's document version and date
  were hardcoded in `standard/build_pdf.py` (`v1.0.0` / `June 2026`) while the
  project had moved on, so the committed PDF was still
  `AGSSH-STD-001-v1.0.0.pdf` and the runner's banner/signed record carried a
  third hand-written `v1.0.0`. `DOC_VER`/`DOC_DATE` now derive from this
  CHANGELOG's newest release heading (fail-closed: a missing or malformed
  heading aborts the build), the PDF is regenerated at the derived version —
  byte-reproducibly, with `SOURCE_DATE_EPOCH` defaulted to the release date —
  and the runner's standard-version constant is generated
  (`internal/rules/version_gen.go`) from the same chain instead of hand-bumped.
- **Documented tooling drift on the 10 dynamic rules.** The informative `tool=`
  field of AG-NET-01/05/07, AG-PRV-01/02/04/05/06, AG-OUT-03 and AG-GOV-06
  (plus the Appendix D tooling row) said "Playwright" while the runner does
  headless verification via `chromedp` and ships no Node. Text-only alignment
  of that field: no rule IDs, severities, profiles, obligations, `check=`,
  `why=`, `fix=` texts or verdicts changed.

### Added

- `standard/sync_readme.py` — injects the generator-derived rule count, family
  count, standard version and PDF filename into marker-delimited spans of
  `README.md` / `standard/README.md` and into the version strings of
  `action.yml` / `.airgap.yml`, so those values can no longer be hand-copied
  and drift. Wired into CI in `--check` mode: fail-closed (a missing marker or
  unparseable source fails the build) with an explicit verdict when in sync.

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

[Unreleased]: https://github.com/fabriziosalmi/agssh/compare/v1.3.2...HEAD
[1.3.2]: https://github.com/fabriziosalmi/agssh/compare/v1.3.1...v1.3.2
[1.3.1]: https://github.com/fabriziosalmi/agssh/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/fabriziosalmi/agssh/compare/v1.2.2...v1.3.0
[1.2.2]: https://github.com/fabriziosalmi/agssh/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/fabriziosalmi/agssh/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/fabriziosalmi/agssh/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/fabriziosalmi/agssh/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/fabriziosalmi/agssh/releases/tag/v1.0.0
