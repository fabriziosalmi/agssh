package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fabriziosalmi/agssh/internal/badge"
	"github.com/fabriziosalmi/agssh/internal/engine"
	"github.com/fabriziosalmi/agssh/internal/httpx"
	"github.com/fabriziosalmi/agssh/internal/manifest"
	"github.com/fabriziosalmi/agssh/internal/report"
	"github.com/fabriziosalmi/agssh/internal/target"
)

const scanUsage = `usage: agssh scan [flags] <url>...

Evaluate one or more live URLs against AGSSH-STD-001 with no config file. The
manifest is synthesized from the flags (same defaults as the MCP agssh_scan
tool: Bronze / L0 / site). Source-plane rules (secrets, vulnerable deps, SBOM,
CI) stay INCONCLUSIVE unless -repo / -dist / -workflows are given.

Exit codes: 0 conformant · 1 non-conformant · 2 usage error · 3 unscannable.

Flags:
`

// multi collects a repeatable string flag (-allow-connect a -allow-connect b).
type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

// runScan implements `agssh scan`. It returns the process exit code.
func runScan(args []string) int {
	fs := flag.NewFlagSet("agssh scan", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, scanUsage)
		fs.PrintDefaults()
	}
	var paths, allowConnect, allowSub, allowEmbeds, allowStorage multi
	profile := fs.String("profile", "Bronze", "target profile (Bronze|Silver|Gold)")
	level := fs.String("level", "L0", "strictness band (L0 strict air-gap | L1 scoped egress | L2 marketing)")
	kind := fs.String("kind", "site", "surface kind (site|client-tool|docs)")
	stateless := fs.Bool("stateless", false, "no cookies/localStorage; satisfies Tier-D anti-framing on header-less hosts")
	privacy := fs.Bool("privacy-surface", false, "referrer leakage matters for this surface (AG-NET-09)")
	genFiles := fs.Bool("generates-files", false, "surface produces downloadable files client-side")
	wasm := fs.Bool("threaded-wasm", false, "surface ships threaded WebAssembly")
	sw := fs.Bool("service-worker", false, "surface registers a service worker")
	zone := fs.String("zone", "", "DNS zone for CAA/DNSSEC/dangling checks (default: registrable domain of the URL)")
	resolver := fs.String("resolver", "", "DNS resolver host[:port] (default: host resolv.conf)")
	timeout := fs.Duration("timeout", 45*time.Second, "per-check timeout")
	asJSON := fs.Bool("json", false, "print the conformance record as JSON on stdout (human summary goes to stderr)")
	out := fs.String("out", "", "also write the conformance record (JSON) to this file")
	badgePath := fs.String("badge", "", "write a self-hosted SVG conformance badge to this path")
	repo := fs.String("repo", "", "repository root for static repo checks (default: none)")
	dist := fs.String("dist", "", "built artifact directory for secrets/source-map/SBOM checks (default: none)")
	workflows := fs.String("workflows", "", "CI workflows directory (default: none)")
	fs.Var(&paths, "path", "extra same-origin path to sample (repeatable)")
	fs.Var(&allowConnect, "allow-connect", "L1+ explicit connect-src origin (repeatable, never '*')")
	fs.Var(&allowSub, "allow-subresource", "L1+ subresource host exempted by AG-NET-02 (repeatable)")
	fs.Var(&allowEmbeds, "allow-embed", "L2 sanctioned third-party embed host (repeatable)")
	fs.Var(&allowStorage, "allow-storage", "functional cookie/localStorage key permitted by AG-PRV-04 (repeatable)")

	// The stdlib flag package stops at the first positional, so `scan <url> -level L2`
	// would silently drop the flags. Re-parse after each positional so flags and
	// URLs can be freely interleaved.
	var urls []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			if err == flag.ErrHelp {
				return 0
			}
			return 2
		}
		if fs.NArg() == 0 {
			break
		}
		urls = append(urls, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	if len(urls) == 0 {
		fs.Usage()
		return 2
	}

	cfg := &manifest.Config{
		TargetProfile: *profile,
		Level:         *level,
		DNS:           manifest.DNS{Resolver: *resolver},
		Allow:         manifest.Allow{Connect: allowConnect, Storage: allowStorage, Embeds: allowEmbeds, Subresources: allowSub},
		Waivers:       manifest.Waivers{Budget: manifest.Budget{MaxCount: 3, MaxWeight: 6, MaxWindowDays: 30}},
	}
	if _, err := cfg.Profile(); err != nil {
		return usageErr(err)
	}
	if _, err := cfg.LevelV(); err != nil {
		return usageErr(err)
	}
	if err := manifest.ValidateAllow(cfg.Allow); err != nil {
		return usageErr(err)
	}
	for _, raw := range urls {
		u, err := target.NormalizeURL(raw)
		if err != nil {
			return usageErr(err)
		}
		cfg.Surfaces = append(cfg.Surfaces, manifest.Surface{
			URL: u, Paths: paths, Kind: *kind, GeneratesFiles: *genFiles,
			ThreadedWASM: *wasm, HasServiceWorker: *sw, Stateless: *stateless, PrivacySurface: *privacy,
		})
	}

	// URL-only scan: point unset source roots at an absolute, never-created path so
	// every source-plane checker resolves to INCONCLUSIVE (fail-closed) instead of
	// silently scanning the current directory. Empty strings are NOT safe: Join("", x)
	// collapses to a CWD-relative read.
	noSrc, err := os.MkdirTemp("", "agssh-scan-norepo-")
	if err != nil {
		return usageErr(fmt.Errorf("cannot allocate a scratch root: %w", err))
	}
	defer os.RemoveAll(noSrc)
	absent := filepath.Join(noSrc, "no-source")
	or := func(v string) string {
		if v == "" {
			return absent
		}
		return v
	}

	human := io.Writer(os.Stdout)
	if *asJSON {
		human = os.Stderr
	}
	allConformant, anyUnscannable := true, false
	var records []*report.Record
	for _, s := range cfg.Surfaces {
		surfCfg := *cfg
		surfCfg.DNS.Zone = *zone
		if surfCfg.DNS.Zone == "" {
			surfCfg.DNS.Zone = target.RegistrableDomain(s.URL)
		}
		rec := engine.Evaluate(&surfCfg, s, engine.Options{
			RepoDir: or(*repo), DistDir: or(*dist), WorkflowsDir: or(*workflows),
			HTTP: httpx.New(*timeout), Now: time.Now(), PerCheck: *timeout, Resolver: *resolver,
		})
		rec.Render(human)
		records = append(records, rec)
		anyUnscannable = anyUnscannable || rec.Unscannable
		allConformant = allConformant && rec.Conformant
	}

	if *badgePath != "" {
		if anyUnscannable {
			fmt.Fprintln(os.Stderr, "badge skipped: a surface was unscannable (no verdict to certify)")
		} else if e := os.WriteFile(*badgePath, badge.RenderAggregate(records), 0o644); e != nil {
			return usageErr(e)
		} else {
			fmt.Fprintf(os.Stderr, "badge written: %s\n", filepath.Clean(*badgePath))
		}
	}

	if *asJSON || *out != "" {
		var data []byte
		if len(records) == 1 {
			data, _ = records[0].JSON()
		} else {
			data, _ = json.MarshalIndent(records, "", "  ")
		}
		if *asJSON {
			fmt.Fprintln(os.Stdout, string(data))
		}
		if *out != "" {
			if e := os.WriteFile(*out, data, 0o644); e != nil {
				return usageErr(e)
			}
			fmt.Fprintf(os.Stderr, "record written: %s\n", filepath.Clean(*out))
		}
	}

	reportPath := ""
	if *out != "" {
		reportPath = filepath.Clean(*out)
	}
	emitGitHubOutputs(allConformant, reportPath)

	// "I could not look" (3) outranks "I looked and it fell short" (1).
	switch {
	case anyUnscannable:
		return 3
	case !allConformant:
		return 1
	}
	return 0
}

func usageErr(err error) int {
	fmt.Fprintln(os.Stderr, "agssh:", err)
	return 2
}
