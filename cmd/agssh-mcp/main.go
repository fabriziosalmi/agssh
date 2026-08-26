// Command agssh-mcp serves the AGSSH-STD-001 runner over the Model Context
// Protocol on stdio. It exposes agssh_scan (evaluate a live URL), agssh_scan_config
// (evaluate an existing .airgap.yml with full repo/CI/supply-chain scope), and
// agssh_list_rules (registry introspection). Register it with an MCP client, e.g.:
//
//	claude mcp add agssh -- agssh-mcp
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/fabriziosalmi/agssh/internal/mcpsrv"
)

// Build metadata, stamped by goreleaser via -ldflags -X main.<name>.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("agssh-mcp %s (commit %s, built %s)\n", version, commit, date)
		return
	}

	// Cancel the server cleanly on SIGINT/SIGTERM so a supervising client can
	// reap the process without a lingering headless-browser child.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := mcpsrv.New(version)
	if err := srv.Run(ctx, &mcp.StdioTransport{}); err != nil && ctx.Err() == nil {
		fmt.Fprintln(os.Stderr, "agssh-mcp:", err)
		os.Exit(1)
	}
}
