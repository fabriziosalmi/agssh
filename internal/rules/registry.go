package rules

import "github.com/fabriziosalmi/agssh/internal/manifest"

// All returns every rule in AGSSH-STD-001 v1.0.0 with its metadata and checker.
// Rules with Plane==PlaneEngine carry a nil Check and are evaluated by the
// engine itself (waiver governance, signing, hermetic-build hints).
func All() []Rule {
	B, S, G := manifest.Bronze, manifest.Silver, manifest.Gold
	return []Rule{
		// ---- §2 AG-NET — Egress & Air-Gap ----
		{"AG-NET-01", "Self-host every runtime dependency", "AG-NET", Must, Critical, B, PlaneStatic, always, chkSelfHostAll},
		{"AG-NET-02", "Override library default CDN loaders", "AG-NET", Must, Critical, B, PlaneStatic, always, chkNoCDNLoaders},
		{"AG-NET-03", "Same-origin workers; constrain worker-src", "AG-NET", Must, High, S, PlaneStatic, always, chkWorkerSrc},
		{"AG-NET-04", "Constrain connect-src", "AG-NET", Must, Critical, B, PlaneStatic, always, chkConnectSrc},
		{"AG-NET-05", "Prove offline operation", "AG-NET", Must, High, S, PlaneDynamic, always, chkOfflineProof},
		{"AG-NET-06", "No third-party connection priming", "AG-NET", Must, Medium, S, PlaneStatic, always, chkNoPriming},
		{"AG-NET-07", "Service Worker hygiene", "AG-NET", Must, High, S, PlaneDynamic, ifServiceWorker, todo("inspect registered SW scope and fetch handler")},
		{"AG-NET-08", "Violation/error reporting stays same-origin", "AG-NET", Must, Medium, S, PlaneStatic, always, chkReportSameOrigin},
		{"AG-NET-09", "External _blank links sever the opener; privacy surfaces sever the referrer", "AG-NET", Must, Medium, B, PlaneStatic, always, chkNoopener},

		// ---- §3 AG-CSP — Content-Security-Policy ----
		{"AG-CSP-01", "Ship a CSP", "AG-CSP", Must, High, B, PlaneStatic, always, chkCSPPresent},
		{"AG-CSP-02", "Deny by default; forbid bypass primitives", "AG-CSP", Must, High, B, PlaneStatic, always, chkDenyDefault},
		{"AG-CSP-03", "Clickjacking control must be header-delivered", "AG-CSP", Must, High, B, PlaneStatic, always, chkClickjack},
		{"AG-CSP-04", "Stage report-only before enforcing", "AG-CSP", Should, Medium, S, PlaneStatic, always, todo("track report-only rollout history")},
		{"AG-CSP-05", "Force HTTPS subresources", "AG-CSP", Must, Medium, S, PlaneStatic, always, chkUpgradeInsecure},
		{"AG-CSP-06", "Trusted Types for DOM sinks", "AG-CSP", Must, High, S, PlaneStatic, always, chkTrustedTypes},

		// ---- §4 AG-HDR — Security Response Headers ----
		{"AG-HDR-01", "HSTS with a real max-age", "AG-HDR", Must, High, B, PlaneStatic, always, chkHSTS},
		{"AG-HDR-01a", "HSTS scope is sticky — gate it", "AG-HDR", Must, High, S, PlaneStatic, always, chkHSTSScope},
		{"AG-HDR-02", "Disable MIME sniffing", "AG-HDR", Must, High, B, PlaneStatic, always, chkNosniff},
		{"AG-HDR-03", "X-Frame-Options", "AG-HDR", Must, High, B, PlaneStatic, always, chkXFO},
		{"AG-HDR-04", "Referrer-Policy", "AG-HDR", Must, Medium, S, PlaneStatic, always, chkReferrer},
		{"AG-HDR-05", "Permissions-Policy", "AG-HDR", Must, Medium, S, PlaneStatic, always, chkPermissionsPolicy},
		{"AG-HDR-06", "Cross-origin isolation for threaded WASM", "AG-HDR", Must, Medium, G, PlaneStatic, ifThreadedWASM, chkCOIso},
		{"AG-HDR-07", "Cache discipline for fingerprinted assets", "AG-HDR", Should, Low, S, PlaneStatic, always, todo("per-asset Cache-Control inspection")},
		{"AG-HDR-08", "TLS floor", "AG-HDR", Must, High, S, PlaneTLS, always, chkTLSFloor},

		// ---- §5 AG-DNS — DNS Trust Anchors ----
		{"AG-DNS-01", "CAA pins certificate issuance", "AG-DNS", Must, High, S, PlaneDNS, always, chkCAA},
		{"AG-DNS-02", "DNSSEC enabled", "AG-DNS", Should, Medium, S, PlaneDNS, always, chkDNSSEC},
		{"AG-DNS-03", "No danglable records (subdomain takeover)", "AG-DNS", Must, High, S, PlaneDNS, always, chkDangling},

		// ---- §6 AG-SUP — Supply Chain ----
		{"AG-SUP-01", "SRI on any unavoidable cross-origin subresource", "AG-SUP", Must, High, S, PlaneStatic, always, chkSRI},
		{"AG-SUP-02", "Pin dependencies by integrity hash", "AG-SUP", Must, High, S, PlaneSupply, always, chkPinnedDeps},
		{"AG-SUP-03", "Reproducible build; pinned toolchain", "AG-SUP", Should, Medium, S, PlaneSupply, always, todo("rebuild and compare artifact digests")},
		{"AG-SUP-04", "No secrets in shipped output", "AG-SUP", Must, High, B, PlaneSupply, always, chkNoSecrets},
		{"AG-SUP-05", "No unintended source maps", "AG-SUP", Should, Low, S, PlaneSupply, always, chkNoSourceMaps},
		{"AG-SUP-06", "No known-vulnerable dependencies", "AG-SUP", Must, High, B, PlaneSupply, always, chkNoKnownVulns},
		{"AG-SUP-07", "SBOM produced and retained", "AG-SUP", Should, Medium, G, PlaneSupply, always, chkSBOM},
		{"AG-SUP-08", "Sign releases / provenance", "AG-SUP", Should, Medium, G, PlaneSupply, always, todo("cosign verify-blob against provenance")},

		// ---- §7 AG-CI — CI Pipeline Hardening ----
		{"AG-CI-01", "Pin Actions to a 40-char SHA", "AG-CI", Must, High, S, PlaneCI, always, chkPinnedActions},
		{"AG-CI-02", "Least-privilege workflow tokens", "AG-CI", Must, High, S, PlaneCI, always, chkLeastPriv},
		{"AG-CI-03", "No untrusted code in privileged context", "AG-CI", Must, Critical, S, PlaneCI, always, chkNoUntrustedPriv},
		{"AG-CI-04", "Secrets are not exposed to forks", "AG-CI", Must, High, S, PlaneCI, always, todo("audit pull_request workflows for secret exposure")},
		{"AG-CI-05", "Protected branch + required checks", "AG-CI", Should, Medium, S, PlaneCI, always, chkBranchProtection},
		{"AG-CI-06", "Automated contributors under the same gate", "AG-CI", Should, Medium, G, PlaneCI, always, todo("verify bot PRs run the required check")},

		// ---- §8 AG-PRV — Privacy & Data Minimization ----
		{"AG-PRV-01", "Zero telemetry by default", "AG-PRV", Must, Critical, B, PlaneStatic, atLevels(manifest.L0, manifest.L1), chkZeroTelemetry},
		{"AG-PRV-02", "No pre-consent egress", "AG-PRV", Must, Critical, B, PlaneDynamic, always, chkPreConsentEgress},
		{"AG-PRV-03", "Self-host fonts", "AG-PRV", Must, High, B, PlaneStatic, always, chkSelfHostFonts},
		{"AG-PRV-04", "Minimize client storage", "AG-PRV", Must, Medium, S, PlaneDynamic, always, todo("enumerate storage at runtime vs allow-list")},
		{"AG-PRV-05", "Cookie attributes hardened", "AG-PRV", Must, High, S, PlaneStatic, always, chkCookieAttrs},
		{"AG-PRV-06", "Third-party embeds sandboxed", "AG-PRV", Must, Medium, S, PlaneStatic, always, chkEmbedsSandboxed},

		// ---- §9 AG-OUT — Output Artifact Integrity ----
		{"AG-OUT-01", "Strip generated-file metadata", "AG-OUT", Must, Medium, S, PlaneStatic, ifFileGen, todo("inspect generated-file metadata fields")},
		{"AG-OUT-02", "Deterministic output", "AG-OUT", Should, Low, G, PlaneStatic, ifFileGen, todo("two runs on same input -> identical bytes")},
		{"AG-OUT-03", "In-browser only, no server round-trip", "AG-OUT", Must, Critical, B, PlaneStatic, ifFileGen, chkInBrowserOnly},

		// ---- §10 AG-GOV — Governance & Conformance Integrity ----
		{"AG-GOV-01", "Waivers can never cover a MUST", "AG-GOV", Must, Critical, B, PlaneEngine, always, nil},
		{"AG-GOV-02", "Waivers auto-expire; the runner enforces it", "AG-GOV", Must, High, S, PlaneEngine, always, nil},
		{"AG-GOV-03", "Deviation budget / debt ceiling", "AG-GOV", Must, High, S, PlaneEngine, always, nil},
		{"AG-GOV-04", "Segregation of duties on waivers", "AG-GOV", Must, High, G, PlaneEngine, always, nil},
		{"AG-GOV-05", "Conformance record is externally derived and signed", "AG-GOV", Must, High, G, PlaneEngine, always, nil},
		{"AG-GOV-06", "Active egress canary", "AG-GOV", Must, High, S, PlaneDynamic, always, chkEgressCanary},
		{"AG-GOV-07", "Build environment is ephemeral and hermetic", "AG-GOV", Must, High, G, PlaneEngine, always, nil},
	}
}
