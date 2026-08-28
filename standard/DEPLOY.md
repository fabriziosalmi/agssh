# Publishing agssh.dev — GitHub Pages + Cloudflare

The plan to make **agssh.dev** a static surface that passes **AGSSH-STD-001 at
Gold / L0** and wears its own `agssh`-generated badge. Three layers:

- **Content** — a purpose-built, CSP-clean static page (`standard/build_site.py` →
  `site/`): one same-origin stylesheet, zero inline styles/scripts, zero
  third-party assets. This is what lets the site pass `AG-NET-01` / `AG-CSP-02`.
- **Edge (Cloudflare)** — injects the headers GitHub Pages cannot set (CSP, HSTS,
  …), enforces the TLS floor, and holds the DNS controls (CAA, DNSSEC). **This
  page is what you set up by hand / Terraform.**
- **Pipeline** — [`.github/workflows/publish-standard.yml`](../.github/workflows/publish-standard.yml)
  builds the site, deploys it, then scans the live URL at Gold with `-sign`
  (keyless cosign, OIDC) and emits the signed record + SBOM + badge.

---

## 1. DNS + TLS (Cloudflare dashboard)

| Setting | Value | Satisfies |
|---|---|---|
| Pages source | **Settings → Pages → Source = GitHub Actions**, **Custom domain = `agssh.dev`** (the workflow also ships a `CNAME` file in the artifact) | serves this repo on the `agssh.dev` Host |
| DNS record | apex `agssh.dev` → `fabriziosalmi.github.io` (`CNAME`, CF proxy **ON** / orange cloud; apex uses CNAME-flattening) | AG-DNS-03 (no dangling) |
| SSL/TLS mode | **Full (strict)** | AG-TLS chain |
| Minimum TLS Version | **TLS 1.2** | AG-HDR-08 (TLS floor) |
| Always Use HTTPS | **On** | AG-CSP-05 / redirect |
| DNSSEC | **Enable** (then add the DS record at your registrar) | AG-DNS-02 |
| CAA records | see below | AG-DNS-01 |

**CAA** — Cloudflare's Universal SSL issues from a small set of CAs, so pin *those*
(a zone with only `iodef`/no `issue` now FAILS `AG-DNS-01`). Add on the apex:

```
agssh.dev.  CAA  0 issue     "pki.goog"
agssh.dev.  CAA  0 issue     "letsencrypt.org"
agssh.dev.  CAA  0 issue     "ssl.com"
agssh.dev.  CAA  0 issuewild "pki.goog"
agssh.dev.  CAA  0 issuewild "letsencrypt.org"
agssh.dev.  CAA  0 iodef     "mailto:fabrizio.salmi@gmail.com"
```

> Verify against the CA Cloudflare actually uses for your cert before locking it
> down — an over-tight CAA can block renewal. Start with the set above (CF's
> documented issuers) and trim once a cert has renewed cleanly.

## 2. Response headers (Cloudflare Rules → *Transform Rules* → *Modify Response Header*, or a Worker)

GitHub Pages cannot set these; Cloudflare must, on every response for `agssh.dev`.
Add each as a **Set static** header (one rule, or one per header):

```http
Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'; upgrade-insecure-requests
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Permissions-Policy: accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()
Cache-Control: public, max-age=600, must-revalidate
```

Header → rule map:

| Header | Rules |
|---|---|
| `Content-Security-Policy` (`default-src 'none'`, only `style-src`/`img-src` = `'self'`) | AG-NET-01/02/04 (every fetch-directive first-party), AG-CSP-01/02, AG-CSP-06 (`require-trusted-types-for`), AG-CSP-05 (`upgrade-insecure-requests`), AG-GOV-06 (`connect-src` inherits `'none'` → the egress canary is blocked) |
| `frame-ancestors 'none'` + `X-Frame-Options: DENY` | AG-CSP-03, AG-HDR-03 (clickjacking, header-delivered) |
| `Strict-Transport-Security` (2y, `includeSubDomains; preload`) | AG-HDR-01, AG-HDR-01a |
| `X-Content-Type-Options: nosniff` | AG-HDR-02 |
| `Referrer-Policy: no-referrer` | AG-HDR-04 |
| `Permissions-Policy` (deny all) | AG-HDR-05 |
| `Cache-Control` | AG-HDR-07 |

> The content already has **no scripts** and **no third-party assets**, so
> `script-src`, `font-src`, `connect-src`, `object-src`, … all inherit
> `default-src 'none'` and pass. `style-src 'self'` / `img-src 'self'` cover the
> one stylesheet and the badge — both same-origin.

## 3. Staging note (AG-CSP-04)

`AG-CSP-04` wants the policy staged **report-only before enforcing**. Roll out in
two steps: first add `Content-Security-Policy-Report-Only:` with the same policy,
confirm the site renders and reports are clean, then switch the header name to
`Content-Security-Policy`.

---

## What the pipeline does (Gold's supply / CI / governance rules)

Once the edge is live, [`publish-standard.yml`](../.github/workflows/publish-standard.yml)
closes the rest of Gold from an **ephemeral OIDC runner** (AG-GOV-07):

- scans `https://agssh.dev` with `agssh -profile Gold -level L0 -sign` — the
  externally-derived, cosign-signed conformance record is `AG-GOV-05`;
- emits an **SBOM** (`AG-SUP-07`) and build provenance (`AG-SUP-08`);
- SHA-pinned Actions, least-privilege tokens, required-check branch protection
  cover `AG-CI-01…06`; zero waivers make `AG-GOV-01…04` trivially satisfied;
- publishes the signed record, the SBOM, and the freshly-scanned **badge** back to
  the site, so `agssh.dev` shows a Gold medal that reproduces from its own record.

The gate is **fail-closed**: if the live scan is not Gold-conformant, the workflow
goes red — the standard that says *prove it* proves it, or admits it can't.
