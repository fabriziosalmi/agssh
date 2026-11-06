// The conformance record agssh writes (internal/report/report.go), and the text
// built from it: status-bar summary and the prompts copied for an AI assistant.
// No vscode import: tested with node --test.

export interface Evidence {
  observed?: string;
  expected?: string;
}

export interface RuleResult {
  rule: string;
  title: string;
  family: string;
  obligation: string;
  severity: string;
  profile: string;
  status: string; // PASS | FAIL | INCONCLUSIVE | N/A
  waived?: boolean;
  evidence?: Evidence;
  error?: string;
}

export interface FixItem {
  rule: string;
  title: string;
  severity: string;
  status: string;
  expected?: string;
  observed?: string;
}

export interface UnassessedItem {
  rule: string;
  title: string;
  family: string;
  severity: string;
  reason?: string;
}

export interface ConformanceRecord {
  standard: string;
  version: string;
  generator?: string;
  generated_at?: string;
  surface: string;
  profile: string;
  level: string;
  unscannable?: boolean;
  unreachable_reason?: string;
  conformant: boolean;
  score: { earned: number; possible: number; pct: number; deviation_debt: number; scored: number };
  results?: RuleResult[];
  fix_queue?: FixItem[];
  unassessed?: UnassessedItem[];
  governance_violations?: string[];
  environment?: { degraded: boolean; reason?: string; missing_tools?: string[] };
}

/** agssh writes one object for one surface and an array for several. */
export function parseRecords(json: string): ConformanceRecord[] {
  const data: unknown = JSON.parse(json);
  const list = Array.isArray(data) ? data : [data];
  for (const r of list) {
    if (!r || typeof r !== "object" || typeof (r as ConformanceRecord).surface !== "string"
      || typeof (r as ConformanceRecord).conformant !== "boolean") {
      throw new Error("agssh output is not a conformance record");
    }
  }
  return list as ConformanceRecord[];
}

export type Verdict = "CONFORMANT" | "NON-CONFORMANT" | "UNSCANNABLE";

export function verdictOf(r: ConformanceRecord): Verdict {
  if (r.unscannable) return "UNSCANNABLE";
  return r.conformant ? "CONFORMANT" : "NON-CONFORMANT";
}

export function scoreText(r: ConformanceRecord): string {
  if (r.unscannable) return "no score";
  return `${Math.round(r.score.pct)}%`;
}

/** One line for the status bar and the tree: worst verdict across surfaces wins. */
export function summary(records: ConformanceRecord[]): { verdict: Verdict; text: string } {
  if (records.some((r) => r.unscannable)) return { verdict: "UNSCANNABLE", text: "unscannable" };
  if (records.every((r) => r.conformant)) {
    return { verdict: "CONFORMANT", text: `${records[0].profile} conformant` };
  }
  const worst = records.filter((r) => !r.conformant).sort((a, b) => a.score.pct - b.score.pct)[0];
  const fails = records.reduce((n, r) => n + (r.fix_queue?.length ?? 0), 0);
  return { verdict: "NON-CONFORMANT", text: `${scoreText(worst)}, ${fails} to fix` };
}

export function passed(r: ConformanceRecord): RuleResult[] {
  return (r.results ?? []).filter((x) => x.status === "PASS");
}

/** How to re-run the check: the caller passes `agssh -config <file>` for a manifest scan. */
export function scanCommand(r: ConformanceRecord, verify?: string): string {
  return verify ?? `agssh scan -profile ${r.profile} -level ${r.level} ${r.surface}`;
}

/** Prompt for one failing or unassessed rule, with the standard's text appended. */
export function fixPrompt(r: ConformanceRecord, ruleId: string, ruleMarkdown: string, verify?: string): string {
  const fix = r.fix_queue?.find((f) => f.rule === ruleId);
  const un = r.unassessed?.find((u) => u.rule === ruleId);
  const lines: string[] = [];
  if (fix) {
    lines.push(`Fix AGSSH-STD-001 rule ${ruleId} (${fix.title}) for ${r.surface}, `
      + `profile ${r.profile}, level ${r.level}. Severity ${fix.severity}.`, "");
    if (fix.observed) lines.push(`Observed: ${fix.observed}`);
    if (fix.expected) lines.push(`Expected: ${fix.expected}`);
    lines.push("", "Make the smallest change in this repository or its deployment config that "
      + "satisfies the rule. Do not weaken the check and do not add a waiver for a MUST.");
  } else if (un) {
    lines.push(`agssh could not assess AGSSH-STD-001 rule ${ruleId} (${un.title}) for ${r.surface}. `
      + "It is fail-closed, so the gate treats it as a failure.", "");
    if (un.reason) lines.push(`Reason: ${un.reason}`);
    lines.push("", "Explain what has to be supplied so the rule can be checked (a scanner on PATH, "
      + "a -repo or -dist directory, a browser), or what change makes it pass.");
  } else {
    lines.push(`AGSSH-STD-001 rule ${ruleId} for ${r.surface} (profile ${r.profile}, level ${r.level}).`);
  }
  lines.push("", `Verify with: ${scanCommand(r, verify)}`, "", "The standard's text for this rule:", "", ruleMarkdown.trim());
  return lines.join("\n") + "\n";
}

/** Prompt for the whole scan: every failing rule, every unassessed one, environment first. */
export function reportPrompt(records: ConformanceRecord[], verify?: string): string {
  const out: string[] = [
    "Fix the AGSSH-STD-001 findings below, highest severity first. For each rule read its text "
      + "with `agssh rule <id>` (or the MCP resource agssh://rules/<id>) before changing anything. "
      + "Do not weaken checks; a MUST can never be waived.",
  ];
  for (const r of records) {
    out.push("", `## ${r.surface} (${r.profile}/${r.level}): ${verdictOf(r)} ${scoreText(r)}`);
    if (r.unscannable) {
      out.push(`Unscannable: ${r.unreachable_reason ?? "the surface could not be fetched"}`);
      continue;
    }
    if (r.environment?.degraded) {
      out.push(`Environment degraded, the score is not reliable: ${r.environment.reason ?? ""}`.trim());
    }
    const fq = r.fix_queue ?? [];
    if (fq.length) {
      out.push("", "Fix queue:");
      for (const f of fq) {
        out.push(`- [${f.severity}] ${f.rule} ${f.title}`);
        if (f.observed) out.push(`  observed: ${f.observed}`);
        if (f.expected) out.push(`  expected: ${f.expected}`);
      }
    }
    const un = r.unassessed ?? [];
    if (un.length) {
      out.push("", "Could not assess (blocks the gate until checked):");
      for (const u of un) out.push(`- ${u.rule} ${u.title}${u.reason ? `: ${u.reason}` : ""}`);
    }
    for (const v of r.governance_violations ?? []) out.push(`Governance violation: ${v}`);
    out.push("", `Verify with: ${scanCommand(r, verify)}`);
  }
  return out.join("\n") + "\n";
}
