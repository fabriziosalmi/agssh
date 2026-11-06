import { test } from "node:test";
import * as assert from "node:assert/strict";
import { candidatePaths, resolveBinary } from "../locate";
import { ConformanceRecord, fixPrompt, parseRecords, reportPrompt, summary } from "../record";
import { csp, esc, renderReport } from "../html";

function rec(over: Partial<ConformanceRecord> = {}): ConformanceRecord {
  return {
    standard: "AGSSH-STD-001", version: "v1.8.1", surface: "https://example.com/", profile: "Bronze", level: "L0",
    conformant: false, score: { earned: 38, possible: 86, pct: 44.2, deviation_debt: 0, scored: 16 },
    results: [{ rule: "AG-HDR-02", title: "Disable MIME sniffing", family: "AG-HDR", obligation: "MUST", severity: "HIGH", profile: "Bronze", status: "PASS" }],
    fix_queue: [{ rule: "AG-NET-01", title: "Self-host every runtime dependency", severity: "CRITICAL", status: "FAIL", observed: "no CSP", expected: "a CSP" }],
    unassessed: [{ rule: "AG-SUP-04", title: "No secrets in shipped output", family: "AG-SUP", severity: "HIGH", reason: "gitleaks not on PATH" }],
    ...over,
  };
}

test("the setting wins, then the first existing install dir, then the bare name", () => {
  assert.equal(resolveBinary(" /x/agssh ", "/h", "darwin", () => false), "/x/agssh");
  const c = candidatePaths("/h", "darwin");
  assert.deepEqual(c, ["/h/.local/bin/agssh", "/opt/homebrew/bin/agssh", "/usr/local/bin/agssh", "/h/go/bin/agssh"]);
  assert.equal(resolveBinary("", "/h", "darwin", (p) => p === c[2]), c[2]);
  assert.equal(resolveBinary(undefined, "/h", "darwin", () => false), "agssh");
});

test("one record is an object, several are an array, anything else is refused", () => {
  assert.equal(parseRecords(JSON.stringify(rec())).length, 1);
  assert.equal(parseRecords(JSON.stringify([rec(), rec()])).length, 2);
  assert.throws(() => parseRecords('{"status":"pending"}'), /not a conformance record/);
});

test("summary: unscannable outranks non-conformant, which outranks conformant", () => {
  assert.equal(summary([rec({ conformant: true }), rec({ unscannable: true })]).verdict, "UNSCANNABLE");
  assert.deepEqual(summary([rec()]), { verdict: "NON-CONFORMANT", text: "44%, 1 to fix" });
  assert.deepEqual(summary([rec({ conformant: true, fix_queue: [] })]), { verdict: "CONFORMANT", text: "Bronze conformant" });
});

test("a fix prompt carries the evidence, the verify command and the standard's text", () => {
  const p = fixPrompt(rec(), "AG-NET-01", "# AG-NET-01: text\n\n## Remediation (how to satisfy)\n\nself-host");
  assert.match(p, /Observed: no CSP/);
  assert.match(p, /Expected: a CSP/);
  assert.match(p, /Verify with: agssh scan -profile Bronze -level L0 https:\/\/example.com\//);
  assert.match(p, /## Remediation \(how to satisfy\)/);
  assert.match(fixPrompt(rec(), "AG-SUP-04", "x", "agssh -config .airgap.yml"), /Reason: gitleaks not on PATH[\s\S]*Verify with: agssh -config .airgap.yml/);
});

test("the report prompt lists fixes, unassessed rules and a degraded environment", () => {
  const p = reportPrompt([rec({ environment: { degraded: true, reason: "no browser" } }), rec({ unscannable: true, unreachable_reason: "dns" })]);
  assert.match(p, /Environment degraded, the score is not reliable: no browser/);
  assert.match(p, /\[CRITICAL\] AG-NET-01/);
  assert.match(p, /AG-SUP-04 No secrets in shipped output: gitleaks not on PATH/);
  assert.match(p, /Unscannable: dns/);
});

test("evidence from the scanned site cannot inject markup into the report panel", () => {
  const evil = `<script>alert(1)</script><img src=x onerror=alert(2)>"'`;
  const html = renderReport([rec({ surface: evil, fix_queue: [{ rule: "AG-NET-01", title: evil, severity: "CRITICAL", status: "FAIL", observed: evil }] })], "N0NCE");
  assert.ok(!html.includes("<script>alert"), "raw script tag leaked");
  assert.ok(!html.includes("<img src=x"), "raw img tag leaked");
  assert.ok(html.includes("&lt;script&gt;alert(1)&lt;/script&gt;"));
  assert.equal(html.match(/<script/g)?.length, 1, "exactly one script element, ours");
  assert.match(html, /<script nonce="N0NCE">/);
  assert.ok(html.includes(`content="${csp("N0NCE")}"`));
  assert.equal(csp("N0NCE"), "default-src 'none'; style-src 'nonce-N0NCE'; script-src 'nonce-N0NCE'");
  assert.equal(esc(`a"b'c&<>`), "a&quot;b&#39;c&amp;&lt;&gt;");
});
