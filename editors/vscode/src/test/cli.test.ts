import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import { BinaryNotFoundError, ruleText, scanConfig, scanUrl } from "../cli";

const RECORD = JSON.stringify({ standard: "AGSSH-STD-001", version: "v1", surface: "https://x/", profile: "Bronze", level: "L0",
  conformant: false, score: { earned: 1, possible: 2, pct: 50, deviation_debt: 0, scored: 1 } });

function fake(script: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "agssh-fake-"));
  const p = path.join(dir, "agssh");
  fs.writeFileSync(p, `#!/bin/sh\n${script}\n`, { mode: 0o755 });
  return p;
}

test("exit 1 (non-conformant) still yields the record", async () => {
  const b = fake(`echo '${RECORD}'; echo 'summary' >&2; exit 1`);
  const r = await scanUrl(b, "https://x/", "Bronze", "L0", 5);
  assert.equal(r.records[0].surface, "https://x/");
  assert.match(r.log, /summary/);
});

test("exit 2 is an error that carries stderr, not an empty result", async () => {
  const b = fake(`echo 'agssh: bad flag -nope' >&2; exit 2`);
  await assert.rejects(scanUrl(b, "https://x/", "Bronze", "L0", 5), /exit 2.*bad flag -nope/s);
});

test("a missing binary is reported as such", async () => {
  await assert.rejects(scanUrl("/nonexistent/agssh", "https://x/", "Bronze", "L0", 5), BinaryNotFoundError);
});

test("config mode reads the record from the -out file and runs in the manifest's directory", async () => {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "agssh-cfg-")));
  const cwdFile = path.join(dir, "cwd.txt");
  const b = fake(`while [ $# -gt 0 ]; do [ "$1" = "-out" ] && out="$2"; shift; done; pwd > '${cwdFile}'; echo '${RECORD}' > "$out"; exit 3`);
  fs.writeFileSync(path.join(dir, ".airgap.yml"), "x: 1\n");
  const r = await scanConfig(b, path.join(dir, ".airgap.yml"), 5);
  assert.equal(r.records.length, 1);
  assert.equal(fs.readFileSync(cwdFile, "utf8").trim(), dir);
});

test("config mode with no record written is an error", async () => {
  const b = fake(`echo 'config: yaml: line 1' >&2; exit 2`);
  await assert.rejects(scanConfig(b, path.join(os.tmpdir(), ".airgap.yml"), 5), /exit 2.*yaml/s);
});

// Contract test against the real binary: the TypeScript types must match what agssh
// actually writes. Skipped when no agssh binary is available.
const real = process.env.AGSSH_BIN || path.join(os.homedir(), ".local", "bin", "agssh");
test("the real agssh: a record parses, fix_queue and unassessed have the expected shape", { skip: !fs.existsSync(real) }, async () => {
  const srv = http.createServer((_q, s) => { s.writeHead(200, { "content-type": "text/html" }); s.end("<!doctype html><title>t</title><script src=\"https://cdn.example.net/x.js\"></script>"); });
  await new Promise<void>((ok) => srv.listen(0, "127.0.0.1", ok));
  const port = (srv.address() as { port: number }).port;
  try {
    const r = await scanUrl(real, `http://127.0.0.1:${port}/`, "Bronze", "L0", 10);
    const rec = r.records[0];
    assert.equal(rec.conformant, false);
    assert.equal(typeof rec.score.pct, "number");
    const net02 = rec.fix_queue?.find((f) => f.rule === "AG-NET-02");
    assert.ok(net02, "a third-party script must put AG-NET-02 in the fix queue");
    assert.equal(typeof net02!.severity, "string");
    assert.ok(Array.isArray(rec.results) && rec.results.every((x) => typeof x.status === "string"));
    const text = await ruleText(real, "AG-NET-02");
    assert.match(text, /## Remediation \(how to satisfy\)/);
    await assert.rejects(ruleText(real, "AG-XXX-99"), /exit 2/);
  } finally {
    srv.close();
  }
});
