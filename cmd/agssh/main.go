// Command agssh is the AGSSH-STD-001 conformance runner. It evaluates each
// declared surface against its target profile by observing the LIVE deployment,
// applies governed waivers, and emits a signed conformance record. Exit codes:
// 0 = conformant, 1 = non-conformant, 2 = usage/internal error.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fabriziosalmi/agssh/internal/engine"
	"github.com/fabriziosalmi/agssh/internal/httpx"
	"github.com/fabriziosalmi/agssh/internal/manifest"
	"github.com/fabriziosalmi/agssh/internal/report"
)

// Build metadata, stamped by goreleaser via -ldflags -X main.<name>.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cfgPath := flag.String("config", ".airgap.yml", "path to .airgap.yml")
	repo := flag.String("repo", ".", "repository root for static repo checks")
	dist := flag.String("dist", "dist", "built artifact directory (secrets / source-maps / SBOM)")
	workflows := flag.String("workflows", ".github/workflows", "CI workflows directory")
	out := flag.String("out", "agssh-report.json", "conformance record output (JSON); '-' = stdout summary only")
	profileOv := flag.String("profile", "", "override target profile (Bronze|Silver|Gold)")
	levelOv := flag.String("level", "", "override level (L0|L1|L2)")
	sign := flag.Bool("sign", false, "sign the record with cosign (required at Gold)")
	artifact := flag.String("artifact", "", "artifact file to bind the digest to")
	author := flag.String("author", os.Getenv("AGSSH_AUTHOR"), "change author (waiver segregation of duties)")
	approversPath := flag.String("approvers", "", "file with one approved waiver-approver per line")
	timeout := flag.Duration("timeout", 45*time.Second, "per-check timeout")
	resolver := flag.String("resolver", "", "DNS resolver host[:port] for CAA/DNSSEC/dangling (default: host resolv.conf)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("agssh %s (commit %s, built %s)\n", version, commit, date)
		return
	}

	cfg, err := manifest.Load(*cfgPath)
	if err != nil {
		fail(err)
	}
	if *profileOv != "" {
		cfg.TargetProfile = *profileOv
		if _, e := cfg.Profile(); e != nil {
			fail(e)
		}
	}
	if *levelOv != "" {
		cfg.Level = *levelOv
		if _, e := cfg.LevelV(); e != nil {
			fail(e)
		}
	}

	approvers := map[string]bool{}
	if *approversPath != "" {
		f, e := os.Open(*approversPath)
		if e != nil {
			fail(e)
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			l := strings.TrimSpace(sc.Text())
			if l != "" && !strings.HasPrefix(l, "#") {
				approvers[l] = true
			}
		}
		f.Close()
	}

	opts := engine.Options{
		RepoDir: *repo, DistDir: *dist, WorkflowsDir: *workflows,
		HTTP: httpx.New(*timeout), Now: time.Now(), Author: *author,
		Approvers: approvers, Sign: *sign, ArtifactPath: *artifact, PerCheck: *timeout,
		Resolver: *resolver,
	}

	allConformant := true
	var records []*report.Record
	for _, s := range cfg.Surfaces {
		rec := engine.Evaluate(cfg, s, opts)
		rec.Render(os.Stdout)
		records = append(records, rec)
		if !rec.Conformant {
			allConformant = false
		}
	}

	if *out != "-" {
		var data []byte
		if len(records) == 1 {
			data, _ = records[0].JSON()
		} else {
			data, _ = json.MarshalIndent(records, "", "  ")
		}
		if e := os.WriteFile(*out, data, 0o644); e != nil {
			fail(e)
		}
		fmt.Fprintf(os.Stderr, "record written: %s\n", filepath.Clean(*out))
	}

	reportPath := ""
	if *out != "-" {
		reportPath = filepath.Clean(*out)
	}
	emitGitHubOutputs(allConformant, reportPath)

	if !allConformant {
		os.Exit(1)
	}
}

// emitGitHubOutputs appends step outputs to $GITHUB_OUTPUT when running inside a
// GitHub Action, so downstream steps can read steps.<id>.outputs.conformant /
// .report. A no-op outside Actions, and best-effort: an unwritable file never
// changes the conformance verdict (the exit code remains authoritative).
func emitGitHubOutputs(conformant bool, reportPath string) {
	path := os.Getenv("GITHUB_OUTPUT")
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agssh: cannot write GITHUB_OUTPUT: %v\n", err)
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "conformant=%t\nreport=%s\n", conformant, reportPath)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "agssh:", err)
	os.Exit(2)
}
