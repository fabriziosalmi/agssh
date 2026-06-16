# agssh

**AGSSH-STD-001** — a property-based, risk-proportional conformance standard for
air-gapped static surfaces (client-side tools, docs, marketing sites) — together
with **`agssh`**, the deterministic, fail-closed runner that enforces it.

```text
standard/   the standard itself: rendered PDF + the canonical generator
cmd/        the agssh CLI
internal/   runner internals (manifest, csp, rules, engine, report)
action.yml  GitHub Action wrapper      Dockerfile  runtime image (Chromium + cosign)
.airgap.yml conformant-by-default starter manifest
examples/   wiring the gate as a required check
```

The rules live as structured data in [`standard/build_pdf.py`](standard/build_pdf.py),
which emits **both** the PDF and the rule manifest from one source — so the
document and the runner cannot drift. The runner is the implementation that
conforms to that standard.

## The standard

[`standard/AGSSH-STD-001-v1.0.0.pdf`](standard/AGSSH-STD-001-v1.0.0.pdf) — 57
rules across 9 families, three cumulative profiles (Gold superset of Silver
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
scanner, an unreachable surface, or a check not implemented in this build all
block. The gate fails on **any** failing MUST, **any** unwaived failing SHOULD,
or **any** governance violation. Exit codes: `0` conformant, `1`
non-conformant, `2` usage/internal error.

### Build & run

```bash
go build -o agssh ./cmd/agssh
./agssh -config .airgap.yml                       # evaluate the live surface(s)
./agssh -profile Gold -sign -artifact dist/bundle.tar.gz \
        -approvers approvers.txt -author "$GIT_AUTHOR"
```

Flags: `-config -repo -dist -workflows -out -profile -level -sign -artifact -author -approvers -timeout`.

### As a GitHub Action

Runs from a prebuilt image (`ghcr.io/fabriziosalmi/agssh`), so no per-run rebuild.

```yaml
- uses: fabriziosalmi/agssh@v1
  id: agssh
  with: { config: .airgap.yml, sign: "true" }   # needs id-token: write for keyless cosign at Gold
- run: echo "conformant=${{ steps.agssh.outputs.conformant }} report=${{ steps.agssh.outputs.report }}"
```

Outputs: `conformant` (`"true"`/`"false"`) and `report` (path to the JSON record).

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

All 57 rules are registered with full metadata; implemented checkers span every
plane. Rules whose verification is genuinely environment- or process-specific
(reproducible-build comparison, branch protection via the GitHub API,
generated-file metadata) are registered `INCONCLUSIVE` with the exact approach to
wire in — they block until proven, and each is a single `Checker` in
`internal/rules`.

## License

[Apache License 2.0](LICENSE) — permissive, with an explicit patent grant. The
runner and its checkers compose freely into any pipeline, and AGSSH-STD-001 stays
openly implementable.
