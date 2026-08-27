# agssh

**AGSSH-STD-001** — a property-based, risk-proportional conformance standard for
air-gapped static surfaces (client-side tools, docs, marketing sites) — together
with **`agssh`**, the deterministic, fail-closed runner that enforces it.

```text
standard/   the standard itself: rendered PDF + the canonical generator
cmd/        the agssh CLI and agssh-mcp (MCP server)
internal/   runner internals (manifest, csp, rules, engine, report, mcpsrv)
action.yml  GitHub Action wrapper      Dockerfile  runtime image (Chromium + cosign)
.airgap.yml conformant-by-default starter manifest
examples/   wiring the gate as a required check
```

The rules live as structured data in [`standard/build_pdf.py`](standard/build_pdf.py),
which emits **both** the PDF and the rule manifest from one source — so the
document and the runner cannot drift. The runner is the implementation that
conforms to that standard.

## The standard

<!-- agssh:std-headline -->[`standard/AGSSH-STD-001-v1.3.2.pdf`](standard/AGSSH-STD-001-v1.3.2.pdf) — 57 rules across 9 families<!-- /agssh:std-headline -->,
three cumulative profiles (Gold superset of Silver
superset of Bronze), assurance tiers (header / meta / runtime / structural),
containment-first verification, governed waivers, and external signed
attestation. Regenerate it with `cd standard && pip install weasyprint && python build_pdf.py`.

## The runner

Single static Go binary. Native DNS (`miekg/dns`) and TLS (`crypto/tls`) — no
`dig`/`testssl`; headless verification via `chromedp` (no Node); signing via
`cosign`.

### Posture: fail-closed

A rule the runner cannot conclusively verify returns `INCONCLUSIVE`, and the
gate treats that exactly like `FAIL`. Nothing is green unless proven — a missing
scanner or a check not implemented in this build both block. The gate fails on
**any** failing MUST, **any** unwaived failing SHOULD, or **any** governance
violation. A surface whose live deployment **cannot be fetched at all** is not
scored against — it is reported as `UNSCANNABLE` (with the transport cause) and
emits no verdict, score, or badge, so an unreachable host can never masquerade as
a low score. Exit codes: `0` conformant, `1` non-conformant, `2` usage/internal
error, `3` a surface was unscannable.

### Build & run

```bash
go build -o agssh ./cmd/agssh
./agssh -config .airgap.yml                       # evaluate the live surface(s)
./agssh -profile Gold -sign -artifact dist/bundle.tar.gz \
        -approvers approvers.txt -author "$GIT_AUTHOR"
```

Flags: `-config -repo -dist -workflows -out -profile -level -sign -artifact -author -approvers -timeout -badge`.

### Conformance badge

`-badge out.svg` emits a **self-hosted** SVG badge — no web font, no external
image, no third-party endpoint — so a project can serve it from its own origin
without breaking its own AG-NET-02. The badge is a deterministic, pure function
of the conformance record:

- **conformant** → the earned tier as its metal (`AGSSH · Gold`), a fail-closed
  claim that reproduces from the same record;
- **non-conformant** → the grey *target* tier plus the weighted score
  (`AGSSH · Gold · 41%`) — the gap, shown for what it is.

The score is a development diagnostic (an `INCONCLUSIVE` is environment-sensitive
and fail-closed); the **medal is the claim**. The percentage is also
**level-relative** — a ratio over the rules in scope at the declared level — so
scores are **not comparable across levels** (a stricter level can score lower on
the same surface, because it evaluates more rules). Compare medals, not numbers.

### As a GitHub Action

Runs from a prebuilt image (`ghcr.io/fabriziosalmi/agssh`), so no per-run rebuild.

```yaml
- uses: fabriziosalmi/agssh@v1
  id: agssh
  with: { config: .airgap.yml, sign: "true" }   # needs id-token: write for keyless cosign at Gold
- run: echo "conformant=${{ steps.agssh.outputs.conformant }} report=${{ steps.agssh.outputs.report }}"
```

Outputs: `conformant` (`"true"`/`"false"`) and `report` (path to the JSON record).

### As an MCP server

`agssh-mcp` exposes the same engine over the [Model Context Protocol](https://modelcontextprotocol.io)
on stdio, so an agent can scan a surface without the build/config/parse dance. It
reuses the runner in-process — no shell-out, no temp files.

```bash
go install github.com/fabriziosalmi/agssh/cmd/agssh-mcp@latest
claude mcp add agssh -- agssh-mcp        # or use the repo's .mcp.json
```

Three read-only tools:

| Tool | Purpose |
|---|---|
| `agssh_scan` | Evaluate a **live URL**; the manifest is synthesized from the arguments (`url`, `profile`, `level`, `kind`, `allow_*`, …). Source-plane rules report `INCONCLUSIVE`. |
| `agssh_scan_config` | Evaluate an existing `.airgap.yml` with full CLI parity — repo / dist / workflow rules against real paths. |
| `agssh_list_rules` | List the rule registry, filterable by `family` and `profile`. No network. |

Each scan returns a human summary **and** the full structured conformance record
(verdict, weighted score, and severity-ranked fix queue) for programmatic use.

`agssh_scan` fetches the caller-supplied URL server-side, so it refuses
loopback/private/link-local targets by default (an SSRF guard enforced at dial
time on the resolved IP); pass `allow_private_targets` to scan a local surface.

### Waiver governance (the draconian heart)

MUSTs are never waivable (AG-GOV-01); the runner enforces expiry against its own
clock (AG-GOV-02); a per-surface debt ceiling caps active waivers (AG-GOV-03); at
Gold each waiver is signed by an approver distinct from the author (AG-GOV-04). A
valid waiver only ever suppresses a **SHOULD** failure. Truthfulness of a
justification stays a human decision — the runner governs the mechanics only.

### Verification planes

| Plane | How | Needs |
|---|---|---|
| static | live headers + HTML + CSP parse | — |
| dns | `miekg/dns` against a validating resolver | — |
| tls | `crypto/tls` legacy-refusal + modern handshake | — |
| dynamic | headless Chromium: offline proof, pre-consent egress, egress canary | a browser |
| supply | `gitleaks`, `osv-scanner`; source-map / SBOM scans | scanners on PATH |
| ci | workflow static analysis (pinning, permissions, untrusted code) | — |
| engine | waiver governance, signing, hermetic-build hints | `cosign` (Gold) |

All <!-- agssh:n-rules -->57<!-- /agssh:n-rules --> rules are registered with full metadata; implemented checkers span every
plane, including branch protection via the GitHub API (AG-CI-05) and runtime
service-worker / client-storage inspection (AG-NET-07 / AG-PRV-04). The remaining
rules whose verification is genuinely process-specific — reproducible-build
comparison, deterministic-output diffing, report-only rollout history — are
registered `INCONCLUSIVE` with the exact approach to wire in: they block until
proven, and each is a single `Checker` in `internal/rules`.

## License

[Apache License 2.0](LICENSE) — permissive, with an explicit patent grant. The
runner and its checkers compose freely into any pipeline, and AGSSH-STD-001 stays
openly implementable.
