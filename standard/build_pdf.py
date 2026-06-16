#!/usr/bin/env python3
# AGSSH-STD-001 v2.0 (draconian revision).
# The YAML manifest + rule index + tooling appendix are all emitted from the
# same RULES source, so normative text and machine-readable artifacts cannot drift.
import html, re

DOC_TITLE = "Air-Gapped Static Surface Hardening"
DOC_SUB   = "A Property-Based, Risk-Proportional Conformance Standard for Client-Side Tools, Docs &amp; Sites"
DOC_VER   = "v1.0.0"
DOC_DATE  = "June 2026"
DOC_AUTHOR= "Fabrizio Salmi"
DOC_ID    = "AGSSH-STD-001"

SEV = {"CRITICAL":"#b91c1c","HIGH":"#c2410c","MEDIUM":"#b45309","LOW":"#475569"}
PROF = {
 "AG-NET-01":"Bronze","AG-NET-02":"Bronze","AG-NET-03":"Silver","AG-NET-04":"Bronze",
 "AG-NET-05":"Silver","AG-NET-06":"Silver","AG-NET-07":"Silver","AG-NET-08":"Silver","AG-NET-09":"Bronze",
 "AG-CSP-01":"Bronze","AG-CSP-02":"Bronze","AG-CSP-03":"Bronze","AG-CSP-04":"Silver","AG-CSP-05":"Silver","AG-CSP-06":"Silver",
 "AG-HDR-01":"Bronze","AG-HDR-01a":"Silver","AG-HDR-02":"Bronze","AG-HDR-03":"Bronze","AG-HDR-04":"Silver",
 "AG-HDR-05":"Silver","AG-HDR-06":"Gold","AG-HDR-07":"Silver","AG-HDR-08":"Silver",
 "AG-DNS-01":"Silver","AG-DNS-02":"Silver","AG-DNS-03":"Silver",
 "AG-SUP-01":"Silver","AG-SUP-02":"Silver","AG-SUP-03":"Silver","AG-SUP-04":"Bronze","AG-SUP-05":"Silver",
 "AG-SUP-06":"Bronze","AG-SUP-07":"Gold","AG-SUP-08":"Gold",
 "AG-CI-01":"Silver","AG-CI-02":"Silver","AG-CI-03":"Silver","AG-CI-04":"Silver","AG-CI-05":"Silver","AG-CI-06":"Gold",
 "AG-PRV-01":"Bronze","AG-PRV-02":"Bronze","AG-PRV-03":"Bronze","AG-PRV-04":"Silver","AG-PRV-05":"Silver","AG-PRV-06":"Silver",
 "AG-OUT-01":"Silver","AG-OUT-02":"Gold","AG-OUT-03":"Bronze",
 "AG-GOV-01":"Bronze","AG-GOV-02":"Silver","AG-GOV-03":"Silver","AG-GOV-04":"Gold","AG-GOV-05":"Gold","AG-GOV-06":"Silver","AG-GOV-07":"Gold",
}
PROF_COLOR = {"Bronze":"#b45309","Silver":"#475569","Gold":"#a16207"}

def fmt(s):
    s = html.escape(s)
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", s)

def code(s):
    return '<pre class="cb">' + html.escape(s) + "</pre>"

# fields: id,title,sev,applies,ct,why,check,fix,tool
RULES = [
 ("§2","Egress &amp; Air-Gap","AG-NET",[
  dict(id="AG-NET-01",title="Self-host every runtime dependency",sev="CRITICAL",
   applies="MUST · L0 L1 L2",ct="static+dynamic",
   why="The third-party egress set of a surface is the UNION of every host it can reach: all CSP fetch-directive sources (script/style/img/font/media/connect/worker/frame/manifest/prefetch-src) plus every runtime sink (fetch, XHR, sendBeacon, EventSource, WebSocket, new Worker, importScripts, WebAssembly.instantiate*, dynamic import). For L0 that set MUST be a subset of {self}. The canonical breach is a browser OCR/codec engine fetched from a CDN on use — the document stays local, the engine does not.",
   check="egress = union(all CSP fetch-dir hosts, all runtime request hosts)\nassert egress ⊆ {self}      # not connect-src alone — the whole set",
   fix="Vendor all assets same-origin; ship the .wasm, workers and data packs from your own origin.",
   tool="Playwright request capture + CSP parser"),
  dict(id="AG-NET-02",title="Override library default CDN loaders",sev="CRITICAL",
   applies="MUST · L0 L1 L2",ct="static",
   why="Tesseract.js (workerPath/corePath/langPath → jsDelivr + the tessdata host), jsPDF (the pdfobject viewer → cdnjs), pdf.js workers and ML model loaders all fetch from a CDN by default unless explicitly repointed. The default is invisible egress that CSP-less testing never reveals until it fires.",
   check="grep dist: jsdelivr|unpkg|cdnjs|tessdata|projectnaptha => 0 hits\nassert every loader path (workerPath/corePath/langPath/…) is same-origin",
   fix="Pass explicit same-origin paths to every loader; treat a surviving default-CDN literal as a build failure.",
   tool="ripgrep over dist/"),
  dict(id="AG-NET-03",title="Same-origin workers; constrain worker-src",sev="HIGH",
   applies="MUST · L0 L1 L2",ct="static",
   why="A Blob worker doing importScripts('https://cdn…'), or a cross-origin module worker, re-introduces code that SRI cannot cover (there is no integrity for importScripts or module workers).",
   check="every importScripts(/new Worker( arg resolves same-origin ;\nCSP: worker-src 'self' ; child-src 'none'",
   fix="Bundle workers locally; point any library workerPath at a same-origin file.",
   tool="AST/regex scan + CSP parser"),
  dict(id="AG-NET-04",title="Constrain connect-src",sev="CRITICAL",
   applies="MUST · L0 L1   (conditional · L2)",ct="static",
   why="The browser-enforced air-gap for XHR/fetch/WebSocket. connect-src 'none' makes that exfiltration channel impossible regardless of any bug or injection. Tools that genuinely need the network declare an explicit allowlist of exact origins — never '*', never a bare scheme.",
   check="parse CSP connect-src:\n  L0 => exactly 'none' ; L1 => literal-origin allowlist (no '*'/https:)\n  L2 => must exclude every unconsented tracker host",
   fix="Set connect-src 'none' for pure client-side tools; for an agent talking to a local LLM scope to that exact origin only.",
   tool="CSP parser"),
  dict(id="AG-NET-05",title="Prove offline operation",sev="HIGH",
   applies="MUST · L0   (SHOULD · L1)",ct="dynamic",
   why="The air-gap claim must be demonstrable, not asserted. A surface that 'should' work offline but was never tested with the network cut is an assumption.",
   check="headless load, abort ALL network after first paint, run the\nfunctional smoke test => success AND zero failed non-self requests",
   fix="Add a CI job that aborts every request post-load and asserts the core flow completes.",
   tool="Playwright route abort"),
  dict(id="AG-NET-06",title="No third-party connection priming",sev="MEDIUM",
   applies="MUST · L0 L1   (SHOULD · L2)",ct="static",
   why="preconnect/dns-prefetch/prefetch to third parties leak intent and warm tracker connections before the visitor interacts at all.",
   check="all rel in {preconnect,dns-prefetch,preload,prefetch,modulepreload}\nhosts ⊆ {self}",
   fix="Remove off-origin resource hints; keep only self-targeted preloads.",
   tool="HTML parser"),
  dict(id="AG-NET-07",title="Service Worker hygiene",sev="HIGH",
   applies="MUST · when a service worker is registered",ct="dynamic",
   why="A service worker is persistent code that intercepts every request and can cache and replay responses. A compromised or over-scoped SW is a durable foothold that survives page reloads.",
   check="SW served same-origin ; narrowest scope ; fetch handlers contact\nonly self ; no remote importScripts ; cache stores only same-origin",
   fix="Register the narrowest scope; never importScripts a remote URL; restrict the cache to same-origin responses.",
   tool="Playwright SW inspection"),
  dict(id="AG-NET-08",title="Violation/error reporting stays same-origin",sev="MEDIUM",
   applies="MUST · L0 L1",ct="static",
   why="CSP report-to / Reporting-Endpoints / NEL pointed at a third-party SaaS collector silently re-introduces egress and ships metadata about every visitor and violation off-origin — defeating the air-gap through the back door.",
   check="Reporting-Endpoints / report-to / NEL targets ⊆ {self}  OR  absent",
   fix="Collect reports at a same-origin endpoint, or disable reporting on air-gapped surfaces.",
   tool="header + CSP parser"),
  dict(id="AG-NET-09",title="External _blank links sever the opener; privacy surfaces sever the referrer",sev="MEDIUM",
   applies="MUST · L0 L1 L2",ct="static",
   why="Property: no <a target=_blank> exposes window.opener to the destination (reverse tabnabbing). The opener is severed by rel containing 'noopener' OR 'noreferrer' ('noreferrer' implies 'noopener' per the HTML spec). On privacy surfaces the referrer is also suppressed. Browsers now imply noopener for target=_blank by default — treat that as defence-in-depth, not as the control.",
   check="for every <a target=_blank>: rel contains 'noopener' or 'noreferrer' ;\non privacy surfaces rel also contains 'noreferrer'",
   fix="Add rel=\"noopener noreferrer\" to external _blank links; noreferrer also blocks referrer leakage.",
   tool="HTML anchor scan"),
 ]),
 ("§3","Content Security Policy","AG-CSP",[
  dict(id="AG-CSP-01",title="Ship a CSP",sev="HIGH",
   applies="MUST · L0 L1 L2",ct="static",
   why="A CSP is the single highest-leverage control on a static surface. Header-delivered is preferred; a <meta http-equiv> CSP is the fallback only for backends that cannot set response headers (GitHub Pages).",
   check="response header content-security-policy present\nOR <meta http-equiv='Content-Security-Policy'> present (record which)",
   fix="Add the policy at the edge where possible; otherwise emit a meta CSP and accept the AG-CSP-03 limitation.",
   tool="header + HTML parser"),
  dict(id="AG-CSP-02",title="Deny by default; enumerate; forbid bypass primitives",sev="HIGH",
   applies="MUST · L0 L1 L2",ct="static",
   why="A permissive CSP is theatre. The baseline denies by default, enumerates only what is used, and removes every known bypass primitive.",
   check="default-src 'none'(or 'self'); object-src 'none'; base-uri 'none'|'self';\nexplicit script/style/img/font/connect/worker/frame/manifest-src;\nform-action 'self'|'none'; NO 'unsafe-eval'; NO 'unsafe-inline' on\nscript-src; NO data:/blob: in script-src; NO wildcard or scheme-only;\n'strict-dynamic' only with nonces",
   fix="Hash or nonce inline scripts; delete unsafe-eval / unsafe-inline(script) / wildcards; add the missing fetch directives explicitly.",
   tool="CSP directive-predicate parser"),
  dict(id="AG-CSP-03",title="Clickjacking control must be header-delivered",sev="HIGH",
   applies="MUST · L0 L1 L2",ct="static",
   why="frame-ancestors, report-uri/report-to and sandbox are IGNORED when a CSP arrives via <meta>. A meta-only surface therefore has NO clickjacking protection from frame-ancestors — it must come from an X-Frame-Options header. Where neither header can be set (pure GitHub Pages), the surface MUST be stateless and the residual risk recorded.",
   check="if meta-CSP contains frame-ancestors => FAIL (ineffective)\nrequire X-Frame-Options header  OR  declared stateless: true",
   fix="Move clickjacking control to an XFO header (front with a CDN if the host can't set it), or keep the surface free of auth and state-changing actions.",
   tool="header + CSP parser"),
  dict(id="AG-CSP-04",title="Stage report-only before enforcing",sev="MEDIUM",
   applies="SHOULD · all (mandatory before first enforcing deploy)",ct="manual",
   why="A CSP that breaks the surface gets disabled in a panic — worse than none. Report-only first turns breakage into telemetry.",
   check="Content-Security-Policy-Report-Only canary in staging before the\nenforcing policy ships ; violations reviewed",
   fix="Deploy report-only, watch violations, then promote to enforcing.",
   tool="staging header + report log"),
  dict(id="AG-CSP-05",title="Force HTTPS subresources",sev="MEDIUM",
   applies="MUST · L0 L1 L2",ct="static",
   why="A single http:// subresource downgrades the whole page's integrity guarantee.",
   check="upgrade-insecure-requests present ; grep subresources 'http://' => 0",
   fix="Add the directive; convert plain-HTTP references to HTTPS or same-origin.",
   tool="CSP parser + HTML scan"),
  dict(id="AG-CSP-06",title="Trusted Types for DOM sinks",sev="HIGH",
   applies="MUST · L0 L1   (SHOULD · L2)",ct="static+dynamic",
   why="Trusted Types eliminate DOM-XSS by forbidding raw string assignment to injection sinks (innerHTML, script.src, eval). For a tool parsing untrusted input — certificates, uploaded files — this closes the highest-impact client-side bug class outright.",
   check="CSP require-trusted-types-for 'script' ;\ntrusted-types <named-policy-list>  (no '*'; 'none' if no policy needed)",
   fix="Enable Trusted Types; route any required HTML through one vetted, sanitizer-backed policy.",
   tool="CSP parser + runtime violation check"),
 ]),
 ("§4","Transport &amp; Response Headers","AG-HDR",[
  dict(id="AG-HDR-01",title="HSTS with a real max-age",sev="HIGH",
   applies="MUST · header-capable backends",ct="static",
   why="max-age=0 DISABLES HSTS and disqualifies the domain from preload while still looking configured — the most common silent regression: the toggle is on, the value is zero.",
   check="Strict-Transport-Security: max-age >= 31536000; includeSubDomains;\npreload      (max-age < 31536000 => FAIL)",
   fix="Set max-age to one year. On Cloudflare this lives under SSL/TLS → Edge Certificates → HSTS — check the value, not just the switch.",
   tool="header parser"),
  dict(id="AG-HDR-01a",title="HSTS scope is sticky — gate it",sev="HIGH",
   applies="MUST · before enabling AG-HDR-01",ct="manual",
   why="includeSubDomains + preload apply to every subdomain and are hard to reverse. Enable them before a subdomain is permanently on HTTPS and you can lock yourself out of it.",
   check="enumerate every subdomain => each returns valid HTTPS\n(GitHub Pages: 'Enforce HTTPS' ON) ; record preload submission state",
   fix="Verify all subdomains over HTTPS first, then add includeSubDomains/preload, then submit to the preload list.",
   tool="subdomain enumeration + curl"),
  dict(id="AG-HDR-02",title="Disable MIME sniffing",sev="HIGH",
   applies="MUST · header-capable",ct="static",
   why="Without nosniff a browser may reinterpret an asset's type and execute content never meant to run.",
   check="X-Content-Type-Options: nosniff",
   fix="Emit the header at the edge / in _headers.",
   tool="header parser"),
  dict(id="AG-HDR-03",title="X-Frame-Options",sev="HIGH",
   applies="MUST · header-capable (pairs with AG-CSP-03)",ct="static",
   why="The reliable, universally-honored clickjacking control; pairs with header CSP frame-ancestors.",
   check="X-Frame-Options: DENY  (or SAMEORIGIN only if same-origin\nframing is genuinely required)",
   fix="DENY unless the surface is intentionally self-embedded.",
   tool="header parser"),
  dict(id="AG-HDR-04",title="Referrer-Policy",sev="MEDIUM",
   applies="MUST · header-capable",ct="static",
   why="Stops the surface from leaking the visited URL to outbound links and resources.",
   check="Referrer-Policy in { no-referrer,\n  strict-origin-when-cross-origin, same-origin }",
   fix="no-referrer for privacy tools; strict-origin-when-cross-origin for marketing.",
   tool="header parser"),
  dict(id="AG-HDR-05",title="Permissions-Policy",sev="MEDIUM",
   applies="MUST · header-capable",ct="static",
   why="Affirmatively switches off powerful features the surface never uses, including the FLoC/Topics opt-out.",
   check="Permissions-Policy disables unused features, e.g.: camera=(),\nmicrophone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
   fix="Default-deny every feature; open only what the tool needs.",
   tool="header parser"),
  dict(id="AG-HDR-06",title="Cross-origin isolation for threaded WASM",sev="MEDIUM",
   applies="MUST · when SharedArrayBuffer / threaded WASM is used",ct="conditional",
   why="Threaded/SIMD WASM (e.g. Tesseract with threads) needs SharedArrayBuffer, which requires cross-origin isolation; this also hardens against Spectre-class cross-origin reads.",
   check="if SAB used => Cross-Origin-Opener-Policy: same-origin AND\nCross-Origin-Embedder-Policy: require-corp\n(Cross-Origin-Resource-Policy: same-origin on served assets)",
   fix="Set COOP+COEP at the edge; serve assets with CORP same-origin. Not needed for single-threaded WASM.",
   tool="header parser + runtime crossOriginIsolated check"),
  dict(id="AG-HDR-07",title="Cache discipline for fingerprinted assets",sev="LOW",
   applies="SHOULD · header-capable",ct="static",
   why="Content-hashed assets are immutable by construction; HTML must never be long-cached or stale tools linger.",
   check="hashed assets (/_astro/*, fingerprinted) => Cache-Control: public,\nmax-age=31536000, immutable ; HTML => no-cache / short",
   fix="Long-cache hashed bundles, short-cache documents.",
   tool="header parser"),
  dict(id="AG-HDR-08",title="TLS floor",sev="HIGH",
   applies="MUST · header-capable",ct="dynamic",
   why="A modern header set over a weak TLS channel is a contradiction. The transport must refuse legacy protocols and ciphers.",
   check="min TLS 1.2 (prefer 1.3); no SSLv3/TLS1.0/1.1; no RC4/3DES/EXPORT;\nOCSP stapling; valid chain",
   fix="Set the edge/CDN TLS profile to modern; disable legacy protocols/ciphers; enable stapling.",
   tool="testssl.sh / sslyze"),
 ]),
 ("§5","DNS &amp; Issuance Trust Anchors","AG-DNS",[
  dict(id="AG-DNS-01",title="CAA pins certificate issuance",sev="HIGH",
   applies="MUST · L0 L1 L2",ct="static",
   why="Without CAA, any public CA can be induced to issue a certificate for your domain. CAA restricts issuance to the CA(s) you actually use and provides an incident contact.",
   check="dig CAA => issue/issuewild restricted to your ACME CA(s) ; iodef set",
   fix="Publish CAA on the apex (and wildcards) naming your CA(s); add an iodef mailto.",
   tool="dig CAA / DNS API"),
  dict(id="AG-DNS-02",title="DNSSEC enabled",sev="MEDIUM",
   applies="SHOULD · L0 L1 L2",ct="static",
   why="DNSSEC prevents forged DNS answers from silently redirecting your domain.",
   check="dig +dnssec shows AD ; DS record present at the registrar",
   fix="Enable DNSSEC at the DNS provider and publish the DS at the registrar.",
   tool="dig +dnssec / delv"),
  dict(id="AG-DNS-03",title="No danglable records (subdomain takeover)",sev="HIGH",
   applies="MUST · L0 L1 L2",ct="static",
   why="A CNAME to a deprovisioned service — a removed Pages site, an unclaimed bucket — is a hijackable subdomain: a live foothold under your brand. Mixed estates (Pages subdomains + a proxied apex) are the usual culprit.",
   check="every CNAME target resolves to a claimed/active resource ;\nno NXDOMAIN / unclaimed-service takeover fingerprints",
   fix="Remove or repoint stale records the moment a service is decommissioned.",
   tool="dnsReaper / subjack"),
 ]),
 ("§6","Supply Chain &amp; Build Integrity","AG-SUP",[
  dict(id="AG-SUP-01",title="SRI on any unavoidable cross-origin subresource",sev="HIGH",
   applies="MUST · L0 L1 L2",ct="static",
   why="Eliminating cross-origin subresources (AG-NET-01) makes this moot — the strongest answer. Where one must remain, integrity pinning stops a compromised CDN swapping the file.",
   check="every cross-origin <script>/<link rel=stylesheet> has integrity=\nAND crossorigin=   ; else FAIL",
   fix="Prefer self-hosting; otherwise add SRI hashes and re-pin on every version bump.",
   tool="HTML parser"),
  dict(id="AG-SUP-02",title="Pin dependencies by integrity hash",sev="HIGH",
   applies="MUST · L0 L1 L2",ct="static",
   why="A floating version is an unsigned cheque to whoever controls the registry or CDN. Pinning by content hash (not just semver) defeats tampering and typosquat republish.",
   check="lockfile with integrity hashes committed ; install uses npm ci /\n--frozen-lockfile ; no '@latest' / unpinned '@vN' / floating CDN",
   fix="Commit the lockfile; install frozen; pin any surviving CDN ref to an exact version + SRI.",
   tool="lockfile lint + ripgrep"),
  dict(id="AG-SUP-03",title="Reproducible build; pinned toolchain",sev="MEDIUM",
   applies="SHOULD · L0 L1 L2",ct="static",
   why="A reproducible build is auditable; a drifting toolchain is not.",
   check=".nvmrc/engines present ; SSG pinned ; base image pinned by digest ;\nbuild is deterministic",
   fix="Pin Node, the SSG, and any container base image by digest.",
   tool="build-config lint"),
  dict(id="AG-SUP-04",title="No secrets in shipped output",sev="HIGH",
   applies="MUST · L0 L1 L2",ct="static",
   why="The build artifact is public the instant it deploys; a baked token or private key is immediately compromised.",
   check="secret scan of the BUILD DIR => 0 hits",
   fix="Scan dist/ in CI; reject on any hit; rotate anything leaked.",
   tool="gitleaks / trufflehog over dist/"),
  dict(id="AG-SUP-05",title="No unintended source maps",sev="LOW",
   applies="SHOULD · L0 L1 L2",ct="static",
   why="Shipped .map files hand an attacker your original source and structure.",
   check="no sourceMappingURL / .map served in production\n(unless intentional and documented)",
   fix="Disable production source-map emission, or host maps privately.",
   tool="ripgrep over dist/"),
  dict(id="AG-SUP-06",title="No known-vulnerable dependencies",sev="HIGH",
   applies="MUST · L0 L1 L2",ct="static",
   why="Shipping a dependency with a known high/critical CVE hands the attacker a public exploit.",
   check="vuln scan of resolved deps => 0 high/critical (or each triaged\nwith a recorded, time-bounded waiver)",
   fix="Upgrade or replace; gate the build; waive only with justification + expiry.",
   tool="osv-scanner / trivy fs / npm audit --audit-level=high"),
  dict(id="AG-SUP-07",title="SBOM emitted and retained",sev="MEDIUM",
   applies="SHOULD · L0 L1 L2",ct="static",
   why="You cannot respond to the next supply-chain CVE for components you cannot enumerate.",
   check="CycloneDX/SPDX SBOM produced per build and retained with the release",
   fix="Generate an SBOM in CI and attach it to the artifact.",
   tool="syft / cdxgen"),
  dict(id="AG-SUP-08",title="Signed releases / build provenance",sev="MEDIUM",
   applies="SHOULD · L0 L1 L2",ct="static",
   why="Signatures and provenance let consumers verify the artifact is the one your pipeline built, unaltered.",
   check="release artifacts signed (Sigstore/cosign or registry provenance);\nverification documented",
   fix="Sign in CI; publish provenance; document verification.",
   tool="cosign / npm provenance / SLSA"),
 ]),
 ("§7","Build Pipeline / CI Hardening","AG-CI",[
  dict(id="AG-CI-01",title="Pin third-party Actions/steps to a full commit SHA",sev="HIGH",
   applies="MUST · L0 L1 L2",ct="static",
   why="A mutable tag (@v4) lets the action's owner — or whoever compromises them — change the code you run with repo write access. A 40-hex commit SHA is immutable.",
   check="every `uses:` referencing a third party pins a full 40-char\ncommit SHA (not a tag or branch)",
   fix="Replace tags with the resolved SHA; let a bot bump SHAs under review.",
   tool="zizmor / actionlint / ripgrep 'uses:.*@(?![0-9a-f]{40})'"),
  dict(id="AG-CI-02",title="Least-privilege workflow tokens",sev="HIGH",
   applies="MUST · L0 L1 L2",ct="static",
   why="The default workflow token is often write-all; a single compromised step inherits it.",
   check="top-level permissions: defaults to read ; write scoped to the\nspecific job that needs it",
   fix="Add an explicit minimal permissions: block at workflow and job level.",
   tool="actionlint / policy check"),
  dict(id="AG-CI-03",title="No untrusted code in a privileged context",sev="CRITICAL",
   applies="MUST · L0 L1 L2",ct="static",
   why="A pull_request_target job (which carries secrets) that checks out and builds/executes the PR head runs attacker-supplied code with your credentials — a classic CI takeover.",
   check="no pull_request_target job checks out head.ref AND runs\nbuild/exec/install with access to secrets",
   fix="Use pull_request (no secrets) for untrusted code, or split so the privileged job never executes PR code.",
   tool="zizmor / workflow analysis"),
  dict(id="AG-CI-04",title="Secrets are not exposed to forks or echoed",sev="HIGH",
   applies="MUST · L0 L1 L2",ct="static",
   why="Secrets reaching fork PRs, or printed to logs, leak to anyone who can open a PR or read a build.",
   check="no secret passed to fork-triggered jobs ; no echo/printenv of\n${{ secrets.* }} ; masking on",
   fix="Gate secret-using jobs to trusted events; never print secrets; treat masking as defence-in-depth, not the control.",
   tool="workflow analysis + log scan"),
  dict(id="AG-CI-05",title="Protected branch with the conformance gate required",sev="MEDIUM",
   applies="SHOULD · L0 L1 L2",ct="manual",
   why="A standard that isn't a required status check is a suggestion. Make AGSSH a merge gate.",
   check="default branch protected ; AGSSH conformance check required ;\nno force-push ; review required",
   fix="Enable branch protection and mark the gate a required status check.",
   tool="repo / org policy"),
  dict(id="AG-CI-06",title="Automated contributors run under scoped identity and the same gate",sev="MEDIUM",
   applies="SHOULD · L0 L1 L2",ct="manual",
   why="Bots and agents that open PRs across many repos are high-value targets and high-blast-radius writers; their commits deserve at least the scrutiny human ones get.",
   check="automation uses a scoped token (least repos/permissions), signs\ncommits, and its PRs pass the AGSSH gate before merge",
   fix="Scope the automation token; enable commit signing; route automated PRs through the same required gate.",
   tool="org policy / token scoping"),
 ]),
 ("§8","Privacy &amp; Consent","AG-PRV",[
  dict(id="AG-PRV-01",title="Zero telemetry on air-gapped surfaces",sev="CRITICAL",
   applies="MUST · L0 L1 (privacy tools)",ct="dynamic",
   why="The correct number of analytics providers on a privacy tool is zero. Anything else contradicts the claim the tool is built on.",
   check="zero analytics signatures AND zero third-party requests\n(subsumed by AG-NET-01)",
   fix="Remove analytics entirely; derive usage signal from edge logs you already control if you must.",
   tool="Playwright request capture"),
  dict(id="AG-PRV-02",title="Prior blocking of non-essential third parties",sev="CRITICAL",
   applies="MUST · L2 (and anywhere a tracker exists)",ct="dynamic",
   why="No analytics / ads / embeds / fonts may fire before explicit opt-in. EU law requires PRIOR blocking; exporting IPs to US analytics is a transfer-law exposure. Loading the tracker on page load and letting the visitor decline afterwards is the exact anti-pattern — the cookie is already set and the hit already sent.",
   check="first visit, NO consent cookie => zero requests to analytics/ad\nhosts AND zero non-essential cookies set",
   fix="Consent Mode with analytics_storage/ad_storage = denied by default, granted only after explicit consent; wire the banner's accept/decline to actually toggle loading. Or drop third-party analytics for an EU-hosted, cookieless one.",
   tool="Playwright (no-consent first-visit capture)"),
  dict(id="AG-PRV-03",title="Self-host fonts",sev="HIGH",
   applies="MUST · L0 L1 L2",ct="static",
   why="Dynamically embedding Google Fonts has been ruled a privacy violation: it ships the visitor's IP to a third party on every load.",
   check="zero fonts.googleapis.com / fonts.gstatic.com references",
   fix="Self-host WOFF2 files in @font-face with font-src 'self'.",
   tool="HTML/CSS scan"),
  dict(id="AG-PRV-04",title="Minimize storage & fingerprinting",sev="MEDIUM",
   applies="MUST · L0 L1   (SHOULD · L2)",ct="dynamic",
   why="Storage and fingerprinting beyond functional need quietly erode the posture and the policy you publish.",
   check="enumerate cookies + localStorage on load against an allowlist ;\nnothing non-functional present",
   fix="Keep only what the tool needs; disclose any remaining storage.",
   tool="Playwright storage inspection"),
  dict(id="AG-PRV-05",title="Cookie attributes where cookies exist",sev="HIGH",
   applies="MUST · when any cookie is set",ct="dynamic",
   why="A cookie without Secure/HttpOnly/SameSite is interceptable, script-readable and CSRF-usable.",
   check="every cookie => Secure ; HttpOnly unless a script must read it ;\nSameSite=Lax|Strict ; __Host- prefix where applicable",
   fix="Set the full attribute set; prefer __Host- prefixed cookies.",
   tool="Playwright cookie inspection"),
  dict(id="AG-PRV-06",title="Third-party embeds isolated and consent-gated",sev="MEDIUM",
   applies="MUST · L2   (forbidden · L0 L1)",ct="dynamic",
   why="An embedded video/map/widget sets third-party cookies and runs third-party code; on a privacy surface it is egress and tracking.",
   check="L0/L1 => zero third-party iframes ; L2 => embeds sandboxed,\nconsent-gated, privacy-mode variant or click-to-load facade",
   fix="Use no-cookie/privacy embeds behind a facade and consent; sandbox the iframe.",
   tool="Playwright + DOM scan"),
 ]),
 ("§9","Output / Document Hygiene","AG-OUT",[
  dict(id="AG-OUT-01",title="Neutralize output metadata",sev="MEDIUM",
   applies="MUST · file-generating tools",ct="dynamic",
   why="Generated files leak their toolchain: a PDF's Info dict AND its XMP packet carry Producer/Creator/timestamps (jsPDF embeds these by default); images carry EXIF/GPS/ICC/maker-notes.",
   check="sample output => Info + XMP neutralized, creation timestamp\nneutral ; image EXIF/GPS/ICC stripped",
   fix="Set neutral document properties and clear XMP; strip image metadata on processing.",
   tool="exiftool / PDF metadata read"),
  dict(id="AG-OUT-02",title="Deterministic output",sev="LOW",
   applies="SHOULD · file-generating tools",ct="dynamic",
   why="Identical inputs yielding byte-identical outputs is both anti-fingerprinting and a reproducibility property.",
   check="two runs on the same input => identical bytes (modulo intended content)",
   fix="Zero or fix timestamps and any other non-deterministic fields.",
   tool="sha256 diff of two runs"),
  dict(id="AG-OUT-03",title="In-browser only, no server round-trip",sev="CRITICAL",
   applies="MUST · file-generating tools",ct="dynamic",
   why="The 'nothing is uploaded' claim must hold at the data-flow level: output is produced and delivered locally.",
   check="output delivered via Blob/object-URL ; no POST of user content\nin the processing path (subsumed by AG-NET-01/04)",
   fix="Generate and download client-side; remove any upload endpoint from the flow.",
   tool="Playwright request capture"),
 ]),
 ("§10","Governance &amp; Conformance Integrity","AG-GOV",[
  dict(id="AG-GOV-01",title="Waivers can never cover a MUST",sev="CRITICAL",
   applies="MUST · all profiles",ct="static",
   why="Conformance integrity needs a hard floor. Every CRITICAL/HIGH MUST is non-waivable by construction; the deviation mechanism exists only for SHOULD items, keeping the load-bearing controls outside any human-justification path.",
   check="no entry in deviations[] references a rule whose obligation is MUST\n=> any such entry FAILS the gate",
   fix="Fix the MUST; never waive it. Re-scope to a lower profile only if the rule genuinely does not apply to the surface.",
   tool="manifest cross-check"),
  dict(id="AG-GOV-02",title="Waivers auto-expire; the runner enforces it",sev="HIGH",
   applies="MUST · when deviations exist",ct="static",
   why="A waiver without enforced expiry becomes permanent debt. The runner compares expires against now; an expired or missing expiry re-enforces the rule immediately, so a waiver can only ever buy bounded time — a fake far-future date still decays on renewal.",
   check="every deviation has expires <= now + max_window ; expired/absent\nexpiry => the rule is re-enforced (fail)",
   fix="Set a real, short expiry; renew under review or remediate.",
   tool="runner clock check"),
  dict(id="AG-GOV-03",title="Deviation budget / debt ceiling",sev="HIGH",
   applies="MUST · L0 L1 L2",ct="static",
   why="Truthfulness cannot be machine-judged, but volume can be capped. A per-surface ceiling on the count and weight of active deviations makes waiving-to-green structurally impossible past the budget.",
   check="sum(active deviation weights) <= budget.max_weight AND\ncount <= budget.max_count   => else FAIL",
   fix="Pay down debt before adding more; the budget forces remediation over accumulation.",
   tool="runner budget check"),
  dict(id="AG-GOV-04",title="Segregation of duties on waivers",sev="HIGH",
   applies="MUST · when deviations exist (Gold)",ct="static",
   why="A self-approved waiver is no control. Each deviation must be signed by an authorized approver distinct from the change author — turning a waiver into an attributable, accountable act rather than anonymous YAML.",
   check="each deviation carries approver != author AND a signature\nverifiable against an approver allowlist",
   fix="Route waivers through a named approver; sign them; reject self-approval.",
   tool="cosign / signed-off-by + approver allowlist"),
  dict(id="AG-GOV-05",title="Conformance record is externally derived and signed",sev="HIGH",
   applies="MUST · L0 L1 L2 (Gold)",ct="dynamic",
   why="A record produced inside a compromised build host can be forged. The authoritative record is produced by an independent runner observing the LIVE deployed surface — headers, egress, DNS and TLS are externally observable — and is signed and bound to the artifact digest, so build-host compromise cannot fabricate production reality.",
   check="record generated against the live URL by an out-of-band runner ;\nsigned (in-toto / cosign) ; bound to artifact digest ; signature verifies",
   fix="Run the gate against production from a separate trusted runner; sign the attestation; verify on consumption.",
   tool="external runner + cosign / in-toto attestation"),
  dict(id="AG-GOV-06",title="Active egress canary - prove the wall, do not observe its silence",sev="HIGH",
   applies="MUST · L0 L1",ct="dynamic",
   why="Observing 'no egress during a test' proves a negative and is defeated by env-detecting, time-delayed or interaction-gated exfiltration. Instead the harness injects a known exfil probe and asserts the policy BLOCKS it — a positive test of a capability boundary that holds in production for every visitor regardless of attacker timing. CSP is the boundary; the canary proves it is real.",
   check="synthetic beacon to a non-allowlisted origin (fetch/img/beacon/ws)\nis blocked by CSP ; a violation is recorded ; production same-origin\nreporting is collecting",
   fix="Lock every fetch-directive to self (AG-NET-01); add the blocked-probe test; collect violation reports same-origin in production.",
   tool="Playwright + injected probe + CSP report endpoint"),
  dict(id="AG-GOV-07",title="Build environment is ephemeral and hermetic",sev="HIGH",
   applies="MUST · L0 L1 L2 (Gold)",ct="static",
   why="A persistent build agent is a persistent foothold that can tamper outputs after the gate. A fresh isolated runner per build, a base image pinned by digest, and short-lived OIDC credentials shrink the window in which the host can forge results — and pair with external verification (AG-GOV-05) so tampering is contradicted by the production scan.",
   check="build runs on a fresh ephemeral runner ; base image pinned by\ndigest ; credentials are short-lived OIDC (no long-lived secrets on agent)",
   fix="Use ephemeral CI runners, digest-pinned images and OIDC federation instead of stored secrets.",
   tool="CI config review + provenance"),
 ]),
]

# ---------------------------------------------------------------- host matrix
HOST_HEADERS=["Backend (edge)","Custom HTTP headers?","CSP","HSTS / XFO / nosniff","Canonical mechanism"]
HOST_ROWS=[
 ["GitHub Pages <span class='muted'>(Fastly)</span>","<b class='no'>No</b>","meta only","not settable as headers","front with a CDN to gain headers; else meta-CSP + stateless surface"],
 ["Cloudflare Pages","<b class='yes'>Yes</b>","header","full","<code>_headers</code> file in the build output"],
 ["Cloudflare <span class='muted'>(proxied origin)</span>","<b class='yes'>Yes</b>","header","full","Transform Rules + Managed Transforms; HSTS via SSL/TLS → Edge Certificates"],
 ["Fastly <span class='muted'>(VCL / Compute)</span>","<b class='yes'>Yes</b>","header","full","<code>set resp.http.*</code> in vcl_deliver, or a Compute service"],
 ["Netlify","<b class='yes'>Yes</b>","header","full","<code>_headers</code> or <code>netlify.toml</code>"],
 ["AWS S3 + CloudFront","<b class='yes'>Yes</b>","header","full","CloudFront Response Headers Policy / Functions / Lambda@Edge"],
]

# ---------------------------------------------------------------- snippets
CF_HEADERS = """# Cloudflare Pages / Netlify  ->  _headers   (header-capable backends)
/*
  Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self' data:; connect-src 'none'; worker-src 'self'; frame-src 'none'; child-src 'none'; manifest-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; require-trusted-types-for 'script'; trusted-types 'none'; upgrade-insecure-requests
  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
  X-Frame-Options: DENY
  X-Content-Type-Options: nosniff
  Referrer-Policy: no-referrer
  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), accelerometer=(), gyroscope=(), magnetometer=(), interest-cohort=()
  Cross-Origin-Opener-Policy: same-origin
  Cross-Origin-Resource-Policy: same-origin

# threaded-WASM (SharedArrayBuffer) tools also set, on HTML + assets:
#   Cross-Origin-Embedder-Policy: require-corp
# if you create a Trusted Types policy (e.g. a sanitizer factory), name it:
#   ... require-trusted-types-for 'script'; trusted-types dompurify
# optional violation reporting MUST stay same-origin (AG-NET-08):
#   Reporting-Endpoints: csp="/_report"   + CSP directive  report-to csp
# Gold residual-channel hardening (the egress canary AG-GOV-06 probes these):
#   add  prefetch-src 'none'  and avoid <link rel=dns-prefetch>; WebRTC is not
#   fully gated by CSP, so disable it if the surface does not use it.
# L1 replaces connect-src 'none' with the exact origin(s). L2 loosens
#   script/style/img to what the page uses, keeps trackers behind consent,
#   and never weakens frame-ancestors / object-src / base-uri.
"""

AIRGAP_YML = """# .airgap.yml  — one per repo. The fleet runner reads this to know what
# to check and at which strictness. The signed JSON output (AG-GOV-05) is
# the conformance record (evidence) and is retained per build.
target_profile: Bronze           # Bronze | Silver | Gold (cumulative)
level: L0                        # L0 strict | L1 scoped-egress | L2 marketing
surfaces:
  - url: https://tools.example.org/
    kind: client-tool            # client-tool | docs | site
    generates_files: true
    threaded_wasm: false
    has_service_worker: false
    stateless: true              # Tier-D: satisfies anti-framing on header-less hosts
backend: github-pages            # drives the host-capability matrix (§11)
dns:
  zone: example.org              # checked for CAA / DNSSEC / dangling CNAME
pipeline:
  enforce_ci_rules: true         # apply the AG-CI family to this repo's workflows
allow:
  connect: []                    # L1 only: explicit origins, never '*'
  storage: []                    # functional cookies / localStorage keys
  embeds:  []                    # L2 only: sanctioned third-party embed hosts
waivers:                         # governance for SHOULD deviations (§10)
  budget: { max_count: 3, max_weight: 6, max_window_days: 30 }
deviations: []                   # SHOULD-only; MUSTs are never waivable (AG-GOV-01)
  # - { rule: AG-SUP-07, reason: "SBOM rollout in progress",
  #     approver: alice, expires: 2026-08-01,        # != author; runner-enforced
  #     evidence: https://github.com/org/repo/issues/123 }
"""

CI_GATE = """# conformance gate (pseudo) — profile-scoped, prod-observed, signed
def gate(surface):
    rules = [r for r in MANIFEST
             if r.in_profile(surface.target_profile)         # Bronze/Silver/Gold
             and r.applies_at(surface.level, surface)]
    results = [run_external(r, surface.live_url) for r in rules]   # black-box, prod
    record  = sign(emit_json(results), artifact_digest)           # AG-GOV-05
    # waiver governance — AG-GOV-01..04
    valid = [w for w in surface.deviations
             if not w.rule.is_must                 # never waive a MUST (AG-GOV-01)
             and w.expires > now                   # auto-expire        (AG-GOV-02)
             and w.signed_by_approver(w)]          # SoD, Gold          (AG-GOV-04)
    assert within_budget(valid, surface.waivers.budget)           # AG-GOV-03
    must_fail = [r for r in results if r.is_must and not r.ok
                 and r.id not in {w.rule for w in valid}]
    ci_fail(must_fail) if must_fail else warn(unwaived_should_fails(results))
# idempotency key = (surface.url, rule.id). Run as a REQUIRED check on the
# protected branch (AG-CI-05), including on automated contributors' PRs (AG-CI-06).
"""

QUICK = """# 60-second drop-in gate (top CRITICAL/HIGH on a live surface + its repo)
U=https://YOUR.SURFACE/ ; Z=YOUR.ZONE
# headers
curl -sI "$U" | grep -iE 'content-security|strict-transport|x-frame|x-content-type|referrer-policy|permissions-policy|cross-origin'
# third-party egress / trackers / default-CDN loaders
curl -s "$U" | grep -oiE 'googletagmanager|gtag|G-[A-Z0-9]{8,}|fonts\\.g(oogleapis|static)|jsdelivr|unpkg|cdnjs|tessdata'
# meta-CSP frame-ancestors trap (ineffective)
curl -s "$U" | grep -oiE 'http-equiv="?content-security[^>]*frame-ancestors'
# DNS trust anchors
dig +short CAA "$Z" ; dig +dnssec +short "$Z" | grep -qi ad && echo "DNSSEC: AD"
# TLS floor
testssl.sh --quiet --protocols "$U"
# supply chain + pipeline (in the repo)
osv-scanner --lockfile=package-lock.json ; gitleaks detect --source dist/ --no-banner
grep -rEn 'uses:[^@]+@(?![0-9a-f]{40})' .github/workflows/    # unpinned Actions
# active egress canary (AG-GOV-06): the proof is a BLOCKED probe, not silence
#   in CI: page injects fetch('https://canary.invalid') and asserts CSP blocks it
# expect: HSTS max-age>=31536000 ; NO analytics/CDN/font hosts ; NO frame-ancestors
#   in a meta CSP ; CAA present ; modern TLS only ; 0 high-CVE deps ; 0 secrets ;
#   0 tag-pinned third-party Actions ; canary probe blocked
"""

# ---------------------------------------------------------------- front matter / appendices (plain strings)
FRONT = """
<h2>§0 &nbsp;Normative Model, Profiles &amp; Assurance</h2>
<div class="lead"><b>Versioning.</b> This standard follows Semantic Versioning: rule IDs are stable and never reused; adding a rule or profile is a MINOR release, tightening or removing a MUST is a MAJOR. <b>This is v1.0.0 — the first stable release</b>, incorporating the responses to an adversarial review: property-based conformance, containment-first verification, external signed attestation, governed waivers, and risk-proportional profiles.</div>

<h3>Normative language</h3>
<p><b>MUST</b>, <b>MUST NOT</b>, <b>SHOULD</b>, <b>SHOULD NOT</b> and <b>MAY</b> follow RFC&nbsp;2119 / RFC&nbsp;8174. A MUST is mandatory and <b>can never be waived</b> (AG-GOV-01). A SHOULD is strongly recommended; a deviation is permitted only under the waiver governance of §10 — bounded, expiring, attributable. There are no silent skips.</p>

<h3>Properties, not mechanisms</h3>
<p>Each rule specifies a security <i>property</i> (e.g. &ldquo;the page cannot be framed&rdquo;, &ldquo;no third-party egress&rdquo;), satisfiable by any control in its equivalence set and recorded with an <i>assurance tier</i>. The standard mandates the property; the mechanism is a documented choice. This is what makes it vendor-neutral: a stateless GitHub&nbsp;Pages site (Tier&nbsp;D) and a header-setting CDN (Tier&nbsp;A) can both satisfy the anti-framing property — pure static hosting is not condemned, and putting a CDN in front is an explicit, recorded expansion of the trust chain, never an implicit mandate.</p>
<table class="grid"><thead><tr><th>Tier</th><th>Enforcement</th><th>Example</th></tr></thead><tbody>
<tr><td><b>A</b></td><td>Browser-enforced via HTTP response header</td><td>X-Frame-Options / header CSP frame-ancestors</td></tr>
<tr><td><b>B</b></td><td>Browser-enforced via &lt;meta&gt; (directives the meta form honors)</td><td>meta CSP script-src / connect-src</td></tr>
<tr><td><b>C</b></td><td>Runtime / script-enforced</td><td>frame-buster on a header-less host</td></tr>
<tr><td><b>D</b></td><td>Structural — the protected asset does not exist</td><td>statelessness removes clickjacking impact entirely</td></tr>
</tbody></table>

<h3>Containment over observation</h3>
<p>Guarantees come from <b>capability boundaries enforced in production for every visitor</b> — a CSP that denies all third-party fetch-directives, an egress allowlist — not from observing the absence of bad behavior in a test. A time-delayed, environment-detecting or interaction-gated exfiltration attempt still strikes the production boundary. Verification therefore proves the boundary <i>blocks a known probe</i> (the egress canary, AG-GOV-06) and is corroborated by same-origin violation reporting from real users; it does not certify a negative. CSP is not a complete egress oracle — WebRTC and DNS-prefetch are residual channels that Gold profiles deny explicitly and the canary probes.</p>

<h3>Conformance is binary — within a declared profile</h3>
<p>Burden must match value, so the rules are partitioned into three cumulative profiles. A surface declares its <b>target profile</b> in <code>.airgap.yml</code>; the gate enforces exactly that profile's subset. A surface is <b>conformant at its target profile</b> iff every MUST in that subset passes and every SHOULD passes or carries a governed deviation. A single failed MUST = non-conformant; the weighted score (§12) only orders remediation.</p>
<table class="grid"><thead><tr><th>Profile</th><th>For</th><th>Adds</th></tr></thead><tbody>
<tr><td><b>Bronze</b> — Baseline</td><td>any static surface (docs, small tools); an afternoon's work, no CI/signing</td><td>egress boundary, CSP lockdown + anti-framing property, core security headers, no secrets in output, no known-CVE deps, no pre-consent telemetry, self-hosted fonts, in-browser-only output</td></tr>
<tr><td><b>Silver</b> — Hardened</td><td>tools handling user data or commercially deployed</td><td>supply-chain integrity, CI hardening, DNS trust anchors, TLS floor, remaining headers/privacy, the egress canary, waiver budget &amp; auto-expiry</td></tr>
<tr><td><b>Gold</b> — Sovereign</td><td>high-assurance / regulated / sovereign-cloud</td><td>release signing &amp; provenance, Trusted Types everywhere, cross-origin isolation, external signed attestation, ephemeral hermetic build, segregation-of-duties waivers</td></tr>
</tbody></table>
<p class="note">Profiles are cumulative: Gold &#8835; Silver &#8835; Bronze. Each rule below is tagged with the lowest profile that requires it.</p>

<h3>Governed waivers (not free text)</h3>
<p>The deviation mechanism is the most-attacked part of any standard, so it is constrained by construction: MUSTs are non-waivable (AG-GOV-01); every waiver carries an enforced expiry after which the runner re-enforces the rule (AG-GOV-02); a per-surface debt ceiling caps total active waivers (AG-GOV-03); and at Gold each waiver is signed by an approver other than the change author (AG-GOV-04). The runner governs the <i>mechanics</i>; the <i>truthfulness</i> of a justification is a named human's accountable decision — this standard does not pretend a deterministic runner can judge intent.</p>

<h3>Evidence &amp; external verification</h3>
<p>The authoritative conformance record is produced by an <b>independent runner observing the live deployed surface</b> (headers, egress, DNS and TLS are externally observable), signed and bound to the artifact digest (AG-GOV-05) — so a compromised build host cannot fabricate production reality. Build-host integrity is treated as a trust dependency defended by ephemeral hermetic builds (AG-GOV-07) and that external attestation; its full specification is out of scope (Appendix&nbsp;F), but it is not assumed away.</p>

<h3>Anti-paralysis</h3>
<p>Rigidity that exhausts teams gets bypassed, so the standard mandates the labor-saving automation alongside the control: a bot keeps pinned Action SHAs current (AG-CI-01) so no one edits 40-character hashes by hand; CSP is staged report-only before enforcing (AG-CSP-04); and a conformant starter (the <code>_headers</code>, <code>.airgap.yml</code> and CI gate) ships green by default, making conformance the path of least resistance rather than an obstacle.</p>
<p class="note">Public, vendor-neutral standard; §10 governs conformance integrity and §11 maps controls to backends. Legal references in Appendix&nbsp;E are informative, not legal advice.</p>
"""

APP_TOOL = """
<h2>Appendix D &nbsp;Tooling Reference <span class="pfx">by check family</span></h2>
<p>Each check family maps to a deterministic, scriptable open-source tool so the standard can be implemented as automation rather than inspection.</p>
<table class="grid"><thead><tr><th>Check family</th><th>Rules</th><th>Recommended tool(s)</th></tr></thead><tbody>
<tr><td>Response headers</td><td>AG-HDR-01..05,07 · AG-NET-08</td><td><code>curl -I</code> + a header parser</td></tr>
<tr><td>CSP directive predicates</td><td>AG-CSP-01..03,05,06 · AG-NET-03,04</td><td>a deterministic CSP parser</td></tr>
<tr><td>Runtime egress / offline / SW / cookies / embeds / output</td><td>AG-NET-01,05,07 · AG-PRV-01,02,04,05,06 · AG-OUT-01..03</td><td>Playwright / Puppeteer (request &amp; storage capture)</td></tr>
<tr><td>Static bundle inspection</td><td>AG-NET-02 · AG-SUP-02,05</td><td>ripgrep over <code>dist/</code></td></tr>
<tr><td>Secrets in build output</td><td>AG-SUP-04</td><td>gitleaks / trufflehog</td></tr>
<tr><td>Vulnerable dependencies</td><td>AG-SUP-06</td><td>osv-scanner / trivy / npm audit</td></tr>
<tr><td>SBOM</td><td>AG-SUP-07</td><td>syft / cdxgen</td></tr>
<tr><td>Signing &amp; provenance</td><td>AG-SUP-08</td><td>cosign / SLSA generators</td></tr>
<tr><td>CI workflow hardening</td><td>AG-CI-01..04</td><td>zizmor / actionlint</td></tr>
<tr><td>DNS trust &amp; takeover</td><td>AG-DNS-01..03</td><td>dig / dnsReaper / subjack</td></tr>
<tr><td>TLS floor</td><td>AG-HDR-08</td><td>testssl.sh / sslyze</td></tr>
<tr><td>Output metadata</td><td>AG-OUT-01</td><td>exiftool / a PDF metadata reader</td></tr>
</tbody></table>
"""

APP_REF = """
<h2>Appendix E &nbsp;Informative References</h2>
<p class="note">Pointers only; consult primary sources. Legal items describe well-known positions and are not legal advice.</p>
<table class="grid"><thead><tr><th>Area</th><th>Reference</th></tr></thead><tbody>
<tr><td>Keyword interpretation</td><td>RFC 2119; RFC 8174</td></tr>
<tr><td>HSTS</td><td>RFC 6797; HSTS preload inclusion criteria (max-age ≥ 1 year, includeSubDomains, preload)</td></tr>
<tr><td>Disclosure / well-known</td><td>RFC 9116 (security.txt); RFC 8615 (well-known URIs)</td></tr>
<tr><td>CSP</td><td>W3C CSP Level 3 — incl. that frame-ancestors, report-uri/report-to and sandbox are ignored when delivered via &lt;meta&gt;</td></tr>
<tr><td>DOM-XSS hardening</td><td>W3C Trusted Types</td></tr>
<tr><td>Cross-origin isolation</td><td>COOP, COEP and the SharedArrayBuffer prerequisite</td></tr>
<tr><td>Supply chain</td><td>SLSA framework; CycloneDX / SPDX (SBOM); OSV; OpenSSF Scorecard</td></tr>
<tr><td>Prior consent (EU)</td><td>ePrivacy Directive 2002/58/EC, Art. 5(3)</td></tr>
<tr><td>Data transfers (EU)</td><td>CJEU C-311/18 (&ldquo;Schrems II&rdquo;, 2020)</td></tr>
<tr><td>Analytics transfers</td><td>Italian Garante — 2022 decision on unlawful Google Analytics transfers</td></tr>
<tr><td>Embedded fonts</td><td>LG München I — 2022 ruling on Google Fonts embedding and IP transfer</td></tr>
</tbody></table>
"""

APP_NONGOALS = """
<h2>Appendix F &nbsp;Trust Dependencies &amp; Non-Goals (Out of Scope to Specify)</h2>
<p>The following are out of scope to <i>specify</i> here — they belong to adjacent standards — but where the threat model depends on them they are treated as <b>trust dependencies with compensating controls</b>, not as assumptions:</p>
<table class="grid"><tbody>
<tr><td><b>Build-host / runner integrity</b> — not assumed hardened. Defended by ephemeral hermetic builds (AG-GOV-07) and by deriving the authoritative conformance record externally from the live surface and signing it (AG-GOV-05), so a compromised build host cannot forge production reality. Its full hardening specification belongs to a separate standard.</td></tr>
<tr><td>Server-side / application security of any dynamic backend (authz logic, injection in server code)</td></tr>
<tr><td>Email-domain anti-abuse (SPF / DKIM / DMARC)</td></tr>
<tr><td>Account, session and identity security beyond the static surface</td></tr>
<tr><td>Accessibility (WCAG) and SEO — important, but a separate concern</td></tr>
</tbody></table>
"""

# ---------------------------------------------------------------- render
def badge(sev):
    return f'<span class="badge" style="background:{SEV[sev]}">{sev}</span>'

def rule_card(r):
    toolline = f'<div class="tool">Tooling: {fmt(r["tool"])}</div>' if r.get("tool") else ""
    prof = PROF.get(r['id'],'Gold'); pc = PROF_COLOR[prof]
    return f"""
<div class="rule" style="border-left-color:{SEV[r['sev']]}">
  <div class="rhead"><span class="rid">{r['id']}</span> {fmt(r['title'])} {badge(r['sev'])}
     <span class="prof" style="color:{pc};border-color:{pc}">{prof}</span>
     <span class="applies">{r['applies']} &nbsp;·&nbsp; {r['ct']}</span></div>
  <div class="why">{fmt(r['why'])}</div>
  <div class="lbl">Check</div>{code(r['check'])}
  <div class="lbl">Remediation</div><div class="fix">{fmt(r['fix'])}</div>
  {toolline}
</div>"""

def section(num,title,prefix,rules):
    return f'<h2>{num} &nbsp;{title} <span class="pfx">{prefix}</span></h2>' + "".join(rule_card(r) for r in rules)

idx_rows=""
for *_,rules in RULES:
    for r in rules:
        idx_rows+=f"<tr><td><code>{r['id']}</code></td><td>{fmt(r['title'])}</td><td>{badge(r['sev'])}</td><td>{PROF.get(r['id'],'Gold')}</td><td>{r['applies'].split('·')[0].strip()}</td></tr>"

def host_table():
    th="".join(f"<th>{h}</th>" for h in HOST_HEADERS)
    trs="".join("<tr>"+"".join(f"<td>{c}</td>" for c in row)+"</tr>" for row in HOST_ROWS)
    return f'<table class="grid"><thead><tr>{th}</tr></thead><tbody>{trs}</tbody></table>'

manifest_yaml="rules:\n"+"".join(
    f"  - id: {r['id']}\n    severity: {r['sev']}\n    check: {r['ct']}\n    tool: {r.get('tool','-')}\n"
    for *_,rules in RULES for r in rules)

sections_html="".join(section(n,t,p,rs) for (n,t,p,rs) in RULES)
n_rules=sum(len(rs) for *_,rs in RULES)
n_fam=len(RULES)

HTML=f"""<!doctype html><html><head><meta charset="utf-8"><style>
@page {{ size:A4; margin:16mm 15mm 18mm 15mm;
  @bottom-left {{ content:"AGSSH-STD-001 · Air-Gapped Static Surface Hardening {DOC_VER}"; font-family:Helvetica,Arial,sans-serif; font-size:7pt; color:#94a3b8; }}
  @bottom-right {{ content:counter(page) " / " counter(pages); font-family:Helvetica,Arial,sans-serif; font-size:7pt; color:#94a3b8; }} }}
* {{ box-sizing:border-box; }}
body {{ font-family:Helvetica,Arial,sans-serif; color:#0f172a; font-size:10.2pt; line-height:1.45; }}
h1 {{ font-size:23pt; margin:0 0 2px; color:#0f172a; letter-spacing:-.4px; }}
h2 {{ font-size:14pt; margin:22px 0 9px; padding-bottom:5px; border-bottom:2px solid #2563eb; color:#0f172a; page-break-after:avoid; }}
h2 .pfx {{ float:right; font-size:9pt; color:#94a3b8; font-weight:normal; letter-spacing:1px; }}
h3 {{ font-size:11.5pt; margin:16px 0 6px; color:#1e293b; page-break-after:avoid; }}
p {{ margin:6px 0; }}
code {{ font-family:'DejaVu Sans Mono',monospace; font-size:8.8pt; background:#f1f5f9; padding:1px 4px; border-radius:3px; color:#0f172a; }}
pre.cb {{ font-family:'DejaVu Sans Mono',monospace; font-size:8.2pt; background:#0f172a; color:#e2e8f0; padding:8px 10px; border-radius:5px; white-space:pre-wrap; word-wrap:break-word; margin:4px 0 2px; line-height:1.38; }}
.muted {{ color:#94a3b8; font-weight:normal; }}
.cover {{ border:1px solid #e2e8f0; border-top:6px solid #2563eb; border-radius:8px; padding:26px 28px; margin-bottom:8px; }}
.cover .sub {{ font-size:12pt; color:#475569; margin:6px 0 16px; }}
.cover .meta {{ font-size:9pt; color:#64748b; }}
.cover .meta b {{ color:#0f172a; }}
.lead {{ background:#f8fafc; border:1px solid #e2e8f0; border-radius:6px; padding:12px 14px; font-size:9.6pt; }}
.rule {{ border:1px solid #e2e8f0; border-left:4px solid #ccc; border-radius:6px; padding:9px 12px; margin:9px 0; page-break-inside:avoid; }}
.rhead {{ font-size:11pt; font-weight:bold; color:#0f172a; }}
.rid {{ font-family:'DejaVu Sans Mono',monospace; font-size:9pt; color:#2563eb; }}
.applies {{ float:right; font-size:7.8pt; color:#64748b; font-weight:normal; }}
.badge {{ color:#fff; font-size:7pt; font-weight:bold; letter-spacing:.5px; padding:2px 6px; border-radius:4px; vertical-align:middle; }}
.prof {{ font-size:6.6pt; font-weight:bold; letter-spacing:.4px; border:1px solid; padding:1px 5px; border-radius:8px; vertical-align:middle; margin-left:2px; }}
.why {{ font-size:9.4pt; color:#334155; margin:5px 0; }}
.lbl {{ font-size:7.6pt; font-weight:bold; letter-spacing:1px; color:#94a3b8; text-transform:uppercase; margin-top:6px; }}
.fix {{ font-size:9.2pt; color:#0f172a; }}
.tool {{ font-size:8.2pt; color:#64748b; font-style:italic; margin-top:4px; }}
table.grid {{ width:100%; border-collapse:collapse; font-size:8.8pt; margin:6px 0; page-break-inside:avoid; }}
table.grid.idxtable {{ page-break-inside:auto; }}
table.grid.idxtable tr {{ page-break-inside:avoid; }}
table.grid th {{ background:#0f172a; color:#fff; text-align:left; padding:6px 8px; font-size:8.4pt; }}
table.grid td {{ border:1px solid #e2e8f0; padding:5px 8px; vertical-align:top; }}
table.grid tr:nth-child(even) td {{ background:#f8fafc; }}
.yes {{ color:#15803d; }} .no {{ color:#b91c1c; }}
.note {{ font-size:8.6pt; color:#64748b; font-style:italic; margin-top:4px; }}
</style></head><body>

<div class="cover">
  <div style="font-size:8pt;letter-spacing:2px;color:#2563eb;font-weight:bold;">DETERMINISTIC SECURITY STANDARD &nbsp;·&nbsp; {DOC_ID} &nbsp;·&nbsp; {DOC_VER}</div>
  <h1>{DOC_TITLE}</h1>
  <div class="sub">{DOC_SUB}</div>
  <div class="meta">{DOC_VER} &nbsp;·&nbsp; {DOC_DATE} &nbsp;·&nbsp; Author <b>{DOC_AUTHOR}</b> &nbsp;·&nbsp; {n_rules} rules · {n_fam} families · Bronze / Silver / Gold profiles · containment-first · external signed attestation</div>
</div>

{FRONT}

<h2>§1 &nbsp;Threat Model &amp; Conformance Levels</h2>
<p class="lead"><b>Scope.</b> Any deployed <i>static surface</i> — a client-side tool, a documentation site, or a marketing site — whose security posture rests on the promise that user data and document content never leave the browser, and ideally that the page performs no unsanctioned network egress at all. The rules are backend-agnostic; <b>§11</b> maps each control onto what GitHub Pages, Cloudflare Pages, proxied Cloudflare, Fastly, Netlify and CloudFront can actually enforce.</p>
<p><b>Threat model.</b> A passive network observer; a compromised or hostile third-party CDN serving the code that touches the document; a hostile embedder (clickjacking); a compromised build pipeline or dependency; data exfiltration through any third-party request; subdomain takeover; and regulatory exposure created by pre-consent third-party calls. Every rule composes into a deterministic conformance gate — the &ldquo;deterministic labyrinth&rdquo;: scan &rarr; per-rule pass/fail &rarr; weighted score &rarr; fix queue &rarr; retained evidence.</p>
<h3>Conformance levels</h3>
<table class="grid"><thead><tr><th>Level</th><th>Meaning</th><th>Defining control</th><th>Typical surface</th></tr></thead><tbody>
<tr><td><b>L0</b> — Air-Gapped Strict</td><td>Client-side tool with no legitimate network need</td><td><code>connect-src 'none'</code>, egress set ⊆ {{self}}</td><td>in-browser TLS / image / PDF utilities</td></tr>
<tr><td><b>L1</b> — Scoped Egress</td><td>Needs the network, but only to known origins</td><td><code>connect-src</code> = explicit allowlist (never <code>*</code>)</td><td>agent talking to a local LLM or one API</td></tr>
<tr><td><b>L2</b> — Public Static</td><td>May include third parties, all non-essential gated</td><td>no pre-consent egress; trackers behind consent</td><td>product / docs / marketing site</td></tr>
</tbody></table>

{sections_html}

<h2>§11 &nbsp;Hosting-Backend Conformance Matrix <span class="pfx">AG-HOST</span></h2>
<p>The same rule is enforceable in different ways — or not at all — depending on whether the edge can set response headers. GitHub Pages is the constrained case: <b>no custom response headers</b>, so CSP exists only as <code>&lt;meta&gt;</code> (with the AG-CSP-03 limitation) and real HSTS/XFO/nosniff need a CDN in front. Everything below can enforce the full header set.</p>
{host_table()}
<p class="note">The DNS family (§5) is independent of the edge: CAA, DNSSEC and dangling-record checks apply at the DNS provider whatever serves the bytes. Mixed estates are common — a project's tool/docs subdomains on GitHub Pages (DNS-only) while the apex is proxied through Cloudflare; headers are settable on the apex and not on the Pages subdomains, and decommissioned Pages subdomains are the prime subdomain-takeover risk (AG-DNS-03). Apply fixes per surface, not per project. For clickjacking specifically, a header-less host reaches the anti-framing property structurally: a stateless surface (Tier&nbsp;D) or a frame-buster (Tier&nbsp;C) satisfies it, so a CDN is not required for conformance — adding one to gain headers is a recorded trust-chain expansion (a new TLS-terminating third party), weighed as such.</p>

<h2>§12 &nbsp;The Deterministic Labyrinth — Verification Harness <span class="pfx">AG-VER</span></h2>
<p>Operationalize the standard as a fleet-level conformance runner. Each repo declares a <b>target profile</b> and its surfaces; the runner evaluates only that profile's applicable rules <b>against the live deployed surface</b>, emits a weighted score and a severity-ordered fix queue, signs a JSON evidence record bound to the artifact digest (AG-GOV-05), and is idempotent on <code>(surface.url, rule.id)</code>. Waivers pass through the governance of §10 — never covering a MUST, auto-expiring, and within the per-surface budget.</p>
<h3>Per-repo declaration</h3>{code(AIRGAP_YML)}
<h3>Canonical header block (header-capable backends)</h3>{code(CF_HEADERS)}
<h3>Conformance gate</h3>{code(CI_GATE)}
<h3>60-second drop-in gate</h3>{code(QUICK)}

<h2>Appendix A &nbsp;Rule Index</h2>
<table class="grid idxtable"><thead><tr><th>ID</th><th>Rule</th><th>Severity</th><th>Profile</th><th>Obligation</th></tr></thead><tbody>{idx_rows}</tbody></table>

<h2>Appendix B &nbsp;Machine-Readable Manifest</h2>
<p class="note">Emitted from the same rule source as this document — spec text, tooling and manifest cannot drift. Feed it to the gate in §12.</p>
{code(manifest_yaml)}

<h2>Appendix C &nbsp;Severity &rarr; Gating Policy</h2>
<table class="grid"><thead><tr><th>Severity</th><th>Weight</th><th>Build effect on failure</th></tr></thead><tbody>
<tr><td>{badge('CRITICAL')}</td><td>8</td><td>block</td></tr>
<tr><td>{badge('HIGH')}</td><td>4</td><td>block</td></tr>
<tr><td>{badge('MEDIUM')}</td><td>2</td><td>advisory — record a deviation to waive</td></tr>
<tr><td>{badge('LOW')}</td><td>1</td><td>advisory — record a deviation to waive</td></tr>
</tbody></table>

{APP_TOOL}
{APP_REF}
{APP_NONGOALS}

</body></html>"""

import os
_here = os.path.dirname(os.path.abspath(__file__))
html_path = os.path.join(_here, "AGSSH-STD-001-" + DOC_VER + ".html")
pdf_path = os.path.join(_here, "AGSSH-STD-001-" + DOC_VER + ".pdf")
with open(html_path, "w") as f:
    f.write(HTML)
print("rules:", n_rules, "| families:", n_fam, "| html bytes:", len(HTML))

# --- machine-readable rule manifest: the SINGLE source the Go runner is tested against.
# internal/rules/skew_test.go fails the build if registry.go diverges from this file, so
# "spec and runner cannot drift" is enforced by a test, not just promised in the README.
manifest_path = os.path.join(_here, "..", "internal", "rules", "manifest.yaml")
with open(manifest_path, "w") as mf:
    mf.write("# GENERATED by standard/build_pdf.py from the RULES source — DO NOT EDIT BY HAND.\n"
             "# The runner's internal/rules/skew_test.go asserts registry.go matches this file,\n"
             "# so the spec and the runner cannot drift. Regenerate: cd standard && python build_pdf.py\n"
             "rules:\n")
    for _sec, _title, _fam, _rs in RULES:
        for _r in _rs:
            _ob = _r["applies"].split("·", 1)[0].strip().split()[0]  # MUST | SHOULD
            mf.write("  - id: %s\n    family: %s\n    obligation: %s\n    severity: %s\n    profile: %s\n"
                     % (_r["id"], _fam, _ob, _r["sev"], PROF.get(_r["id"], "Gold")))
print("manifest:", n_rules, "rules ->", os.path.relpath(manifest_path, _here))
try:
    from weasyprint import HTML as _WP
    _WP(html_path).write_pdf(pdf_path)
    print("wrote", pdf_path)
except Exception as e:
    print("HTML written to", html_path, "- install weasyprint to render the PDF:", e)
