# agssh for VS Code

Scan a live URL or an `.airgap.yml` against [AGSSH-STD-001](https://agssh.dev/) without
leaving the editor. The extension is a thin shell over the `agssh` CLI: every verdict,
score and rule text comes from the binary, so the editor shows exactly what CI shows.

## What it adds

- **agssh view** in the activity bar: one node per surface with its verdict and score,
  then the fix queue (FAIL, highest severity first), the rules that could not be
  assessed (fail-closed, they block the gate) and the rules that passed.
- **Report panel**: the same content as a page, with the observed and expected
  evidence for every failing rule.
- **Copy Fix Prompt for AI**: per rule or for the whole report. The prompt carries the
  evidence, the command to verify the fix and the standard's own text for the rule
  (from `agssh rule <id>`). Paste it into Copilot Chat or Claude.
- **Rule text**: opens the standard's rationale, check, remediation and tooling for a
  rule as Markdown.
- **Status bar**: the worst verdict across the scanned surfaces; click to open the report.

## Commands

| Command | What it runs |
|---|---|
| agssh: Scan URL... | `agssh scan -json -profile <p> -level <l> <url>` |
| agssh: Scan .airgap.yml | `agssh -config .airgap.yml -out <tmp>` in the manifest's directory |
| agssh: Rescan | the last scan again |
| agssh: Open Report | the report panel |
| agssh: Copy Fix Prompt for the Whole Report | the prompt for every finding |

## Requirements

- The `agssh` binary: `go install github.com/fabriziosalmi/agssh/cmd/agssh@latest`, or a
  [release archive](https://github.com/fabriziosalmi/agssh/releases). The extension looks
  in `agssh.binaryPath`, then `~/.local/bin`, `/opt/homebrew/bin`, `/usr/local/bin`,
  `~/go/bin`, then `PATH`.
- Chrome or Chromium for the dynamic checks. agssh finds a standard install on its own;
  otherwise set `AGSSH_CHROME`. Without a browser those rules stay INCONCLUSIVE and the
  view says the environment is degraded.

## Settings

| Setting | Default | Meaning |
|---|---|---|
| `agssh.binaryPath` | empty | Path to `agssh` |
| `agssh.profile` | `Bronze` | Profile for Scan URL |
| `agssh.level` | `L0` | Level for Scan URL |
| `agssh.timeoutSeconds` | `45` | Per-check timeout |

## MCP

The agent side is the `agssh-mcp` server, shipped next to `agssh`. See the
[main README](https://github.com/fabriziosalmi/agssh#as-an-mcp-server) to register it with
Claude Code or Copilot.

## Security

Evidence in a report comes from the scanned site. The report panel escapes every value
and runs under a CSP that allows only its own nonce for styles and scripts.
