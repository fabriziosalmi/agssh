# agssh — Air-Gapped Static Surface Hardening

**Prove your static site makes zero unexpected network calls — deterministically, on every push.**

A *surface* — a client-side tool, a docs site, a marketing page — should talk only
to its own origin. But nothing stops a CDN font, a stray analytics beacon, or a
wide-open CSP from quietly turning the browser into a data-exfiltration path.
**AGSSH-STD-001** (the Air-Gapped Static Surface Hardening standard) pins that
property down, and **`agssh`** is the deterministic, fail-closed runner that
enforces it — against the *live* deployment, not a promise. Built for teams
shipping static or client-side surfaces where privacy and supply-chain integrity
*are* the product.

[![release](https://img.shields.io/github/v/release/fabriziosalmi/agssh?sort=semver&label=release)](https://github.com/fabriziosalmi/agssh/releases)
[![ci](https://github.com/fabriziosalmi/agssh/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/fabriziosalmi/agssh/actions/workflows/ci.yml)
[![standard](https://img.shields.io/badge/AGSSH--STD--001-57%20rules%20·%209%20families-2563eb)](RULES.md)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

## Quick start

Point it at a live URL and read the verdict — no config file to write, no build
step, just pass the target inline (needs a Go toolchain; for a no-Go path use the
Action or the `ghcr.io/fabriziosalmi/agssh` image):

```bash
go install github.com/fabriziosalmi/agssh/cmd/agssh@latest
agssh -config <(echo 'target_profile: Bronze
level: L0
surfaces: [{url: "https://your-surface.example/", kind: site, stateless: true}]')
```

You get a verdict, then a severity-ranked queue of what to fix — and, kept separate,
what could not be checked (fail-closed, never a silent pass):

```text
AGSSH-STD-001 v1.5.1 — https://example.com/ @ Bronze/L0
Verdict: NON-CONFORMANT   Score: 42/86 (49%)
Rules: 7 PASS · 8 FAIL · 1 INCONCLUSIVE · 0 waived · 0 N/A

Fix queue (FAIL only, highest severity first):
  [CRITICAL] AG-NET-01 Self-host every runtime dependency
         observed: no CSP; fetch-directives fall back to the browser's wildcard-open defaults
         expected: a CSP locking every fetch-directive to 'self'/'none'
  [HIGH]     AG-CSP-01 Ship a CSP
         observed: no Content-Security-Policy
  … 6 more …
Could not assess (1 — unverified, fail-closed; supply what's missing):
  AG-SUP-04 No secrets in shipped output   (gitleaks not on PATH)
```

Or drop the conformant-by-default manifest into your repo and gate every push:

```yaml
# .github/workflows/conformance.yml
- uses: fabriziosalmi/agssh@v1          # pin to a SHA in production
  with: { config: .airgap.yml }
```

Or let an agent scan a surface over MCP, in-process:

```bash
go install github.com/fabriziosalmi/agssh/cmd/agssh-mcp@latest
claude mcp add agssh -- agssh-mcp        # then: "scan https://example.com with agssh"
```

Three ways in, one idea: **nothing is green unless proven.**

## The standard

<!-- agssh:std-headline -->[`standard/AGSSH-STD-001-v1.5.1.pdf`](standard/AGSSH-STD-001-v1.5.1.pdf) — 57 rules across 9 families<!-- /agssh:std-headline -->,
browsable as [**`RULES.md`**](RULES.md). The rules live as structured data in
[`standard/build_pdf.py`](standard/build_pdf.py), which emits the PDF, `RULES.md`,
**and** the runner's rule manifest from one source — so the document and the runner
cannot drift.

|  | |
|---|---|
| **9 families** | egress (`AG-NET`), CSP (`AG-CSP`), headers (`AG-HDR`), DNS (`AG-DNS`), supply-chain (`AG-SUP`), CI (`AG-CI`), privacy (`AG-PRV`), output (`AG-OUT`), governance (`AG-GOV`) |
| **3 cumulative profiles** | **Bronze ⊂ Silver ⊂ Gold** — raise the target as the surface's value grows |
| **3 strictness levels** | **L0** strict air-gap · **L1** scoped egress · **L2** marketing |
| **Assurance tiers** | header → meta → runtime → structural — how strong the evidence is, not just whether a box is ticked |

Full normative text (*why · check · fix · tool* per rule) is in the PDF; the
one-line-per-rule index is [`RULES.md`](RULES.md).

## The runner

A single static Go binary. Native DNS (`miekg/dns`) and TLS probing (`crypto/tls`
plus a raw TLS-1.0 `ClientHello` for legacy-refusal) — no `dig`/`testssl`; headless
verification via `chromedp` (no Node); signing via `cosign`.

### Posture: fail-closed

A rule the runner cannot conclusively verify returns `INCONCLUSIVE`, and the gate
treats that exactly like `FAIL`. Nothing is green unless proven — a missing scanner
or a check not implemented in this build both block. The gate fails on **any**
failing MUST, **any** unwaived failing SHOULD, or **any** governance violation. A
surface whose live deployment **cannot be fetched at all** is reported as
`UNSCANNABLE` (with the transport cause) and emits no verdict, score, or badge — an
unreachable host can never masquerade as a low score.

**Exit codes:** `0` conformant · `1` non-conformant · `2` usage/internal error ·
`3` a surface was unscannable.

### Verification planes

| Plane | How | Needs |
|---|---|---|
| static | live headers + HTML + CSP parse | — |
| dns | `miekg/dns` against a validating resolver | — |
| tls | raw-socket TLS-1.0 `ClientHello` (legacy refusal) + `crypto/tls` modern handshake | — |
| dynamic | headless Chromium: offline proof, pre-consent egress, egress canary | a browser |
| supply | `gitleaks`, `osv-scanner`; source-map / SBOM scans | scanners on `PATH` |
| ci | workflow static analysis (pinning, permissions, untrusted code) | — |
| engine | waiver governance, signing, hermetic-build hints | `cosign` (Gold) |

All <!-- agssh:n-rules -->57<!-- /agssh:n-rules --> rules are registered with full metadata; implemented checkers span
every plane, including branch protection via the GitHub API (AG-CI-05) and runtime
service-worker / client-storage inspection (AG-NET-07 / AG-PRV-04). A handful of
rules whose verification is process-specific or not yet automated in this build —
reproducible-build comparison, deterministic-output diffing, report-only rollout
history — are registered `INCONCLUSIVE` with the exact approach to wire in: they
block until proven, and each is a single `Checker` in `internal/rules`.

### Build & run

```bash
go build -o agssh ./cmd/agssh
./agssh -config .airgap.yml                       # evaluate the live surface(s)
./agssh -profile Gold -sign -artifact dist/bundle.tar.gz \
        -approvers approvers.txt -author "$GIT_AUTHOR"
```

Flags: `-config -repo -dist -workflows -out -profile -level -sign -artifact -author -approvers -timeout -resolver -badge -version`.

The output splits what you must fix from what could not be checked: a **Fix queue**
(FAIL only, severity-ranked) and a **Could not assess** list (INCONCLUSIVE, with the
reason). A degraded environment — no headless browser, a missing scanner — is called
out at the top, so a partial scan never looks as confident as a complete one.

## Conformance badge

`-badge out.svg` emits a **self-hosted** SVG badge — no web font, no external image,
no third-party endpoint — so a project can serve it from its own origin without
breaking its own `AG-NET-02`. It is a deterministic, pure function of the record:

- **conformant** → the earned tier as its metal (`AGSSH · Gold`), a fail-closed
  claim that reproduces from the same record;
- **non-conformant** → the grey *target* tier plus the weighted score
  (`AGSSH · Gold · 41%`) — the gap, shown for what it is.

The score is a development diagnostic (an `INCONCLUSIVE` is environment-sensitive and
fail-closed) and is **level-relative** — a ratio over the rules in scope at the
declared level, not comparable across levels. Compare medals, not numbers; the
**medal is the claim.**

## As a GitHub Action

Runs from a prebuilt image (`ghcr.io/fabriziosalmi/agssh`), so no per-run rebuild.

```yaml
- uses: fabriziosalmi/agssh@v1
  id: agssh
  with: { config: .airgap.yml, sign: "true" }   # needs id-token: write for keyless cosign at Gold
- run: echo "conformant=${{ steps.agssh.outputs.conformant }} report=${{ steps.agssh.outputs.report }}"
```

Outputs: `conformant` (`"true"`/`"false"`) and `report` (path to the JSON record).
A ready-to-adapt workflow is in [`examples/workflow.yml`](examples/workflow.yml).

## As an MCP server

`agssh-mcp` exposes the same engine over the [Model Context Protocol](https://modelcontextprotocol.io)
on stdio, so an agent can scan a surface without the build/config/parse dance. It
reuses the runner in-process — no shell-out, no temp files.

```bash
go install github.com/fabriziosalmi/agssh/cmd/agssh-mcp@latest
claude mcp add agssh -- agssh-mcp        # or use the repo's .mcp.json
```

| Tool | Purpose |
|---|---|
| `agssh_scan` | Evaluate a **live URL**; the manifest is synthesized from the arguments (`url`, `profile`, `level`, `kind`, `allow_*`, …). Source-plane rules report `INCONCLUSIVE`. |
| `agssh_scan_config` | Evaluate an existing `.airgap.yml` with full CLI parity — repo / dist / workflow rules against real paths. |
| `agssh_list_rules` | List the rule registry, filterable by `family` and `profile`. No network. |

Each scan returns a human summary **and** the full structured record (verdict,
weighted score, severity-ranked fix queue, `unassessed` list, `environment` block).
`agssh_scan` fetches the caller-supplied URL server-side, so it refuses
loopback/private/link-local targets by default (an SSRF guard enforced at dial time
on the resolved IP); pass `allow_private_targets` to scan a local surface.

## Waiver governance (the draconian heart)

MUSTs are never waivable (AG-GOV-01); the runner enforces expiry against its own
clock (AG-GOV-02); a per-surface debt ceiling caps active waivers (AG-GOV-03); at
Gold each waiver is signed by an approver distinct from the author (AG-GOV-04). A
valid waiver only ever suppresses a **SHOULD** failure. Truthfulness of a
justification stays a human decision — the runner governs the mechanics only.

## Repository layout

```text
standard/   the standard itself: rendered PDF + the canonical generator (build_pdf.py)
RULES.md    browsable index of all 57 rules (generated — never drifts)
cmd/        the agssh CLI and agssh-mcp (MCP server)
internal/   runner internals (manifest, csp, rules, engine, report, mcpsrv, badge)
action.yml  GitHub Action wrapper       Dockerfile  runtime image (Chromium + cosign)
.airgap.yml conformant-by-default starter manifest   examples/  wiring the gate
```

## Contributing

The rules are single-sourced in [`standard/build_pdf.py`](standard/build_pdf.py);
never hand-edit the generated `manifest.yaml` / `RULES.md` / `version_gen.go`. See
[`CONTRIBUTING.md`](CONTRIBUTING.md) for the build/test/regenerate loop and the
fail-closed invariant, and [`SECURITY.md`](SECURITY.md) to report a vulnerability
(a check that can be made to report a false `PASS` is in scope).

## License

[Apache License 2.0](LICENSE) — permissive, with an explicit patent grant. The runner
and its checkers compose freely into any pipeline, and AGSSH-STD-001 stays openly
implementable.
