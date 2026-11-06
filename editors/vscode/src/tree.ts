import * as vscode from "vscode";
import { ConformanceRecord, passed, scoreText, verdictOf } from "./record";

type Group = "fix" | "unassessed" | "passed";

export type Node =
  | { kind: "surface"; i: number }
  | { kind: "note"; text: string; icon: string; color?: string }
  | { kind: "group"; i: number; group: Group }
  | { kind: "item"; i: number; group: Group; rule: string; title: string; severity: string; tip: string };

const PASS = new vscode.ThemeColor("testing.iconPassed");
const FAIL = new vscode.ThemeColor("testing.iconFailed");
const WARN = new vscode.ThemeColor("editorWarning.foreground");

function severityIcon(sev: string): vscode.ThemeIcon {
  if (sev === "CRITICAL" || sev === "HIGH") return new vscode.ThemeIcon("error", FAIL);
  if (sev === "MEDIUM") return new vscode.ThemeIcon("warning", WARN);
  return new vscode.ThemeIcon("info");
}

export class ResultsTree implements vscode.TreeDataProvider<Node> {
  private records: ConformanceRecord[] = [];
  private readonly changed = new vscode.EventEmitter<Node | undefined>();
  readonly onDidChangeTreeData = this.changed.event;

  set(records: ConformanceRecord[]): void {
    this.records = records;
    this.changed.fire(undefined);
  }

  record(i: number): ConformanceRecord | undefined {
    return this.records[i];
  }

  getChildren(n?: Node): Node[] {
    if (!n) return this.records.map((_, i) => ({ kind: "surface", i }));
    if (n.kind === "surface") {
      const r = this.records[n.i];
      if (r.unscannable) {
        return [{ kind: "note", text: `Could not fetch: ${r.unreachable_reason ?? "unknown cause"}`, icon: "warning", color: "warn" }];
      }
      const out: Node[] = [];
      if (r.environment?.degraded) {
        out.push({ kind: "note", text: `Degraded, score not reliable: ${r.environment.reason ?? ""}`, icon: "warning", color: "warn" });
      }
      for (const v of r.governance_violations ?? []) out.push({ kind: "note", text: `Governance: ${v}`, icon: "law", color: "fail" });
      out.push({ kind: "group", i: n.i, group: "fix" }, { kind: "group", i: n.i, group: "unassessed" },
        { kind: "group", i: n.i, group: "passed" });
      return out;
    }
    if (n.kind === "group") {
      const r = this.records[n.i];
      if (n.group === "fix") {
        return (r.fix_queue ?? []).map((f) => ({
          kind: "item", i: n.i, group: n.group, rule: f.rule, title: f.title, severity: f.severity,
          tip: [f.observed && `observed: ${f.observed}`, f.expected && `expected: ${f.expected}`].filter(Boolean).join("\n\n"),
        }));
      }
      if (n.group === "unassessed") {
        return (r.unassessed ?? []).map((u) => ({
          kind: "item", i: n.i, group: n.group, rule: u.rule, title: u.title, severity: u.severity, tip: u.reason ?? "",
        }));
      }
      return passed(r).map((p) => ({
        kind: "item", i: n.i, group: n.group, rule: p.rule, title: p.title, severity: p.severity, tip: "",
      }));
    }
    return [];
  }

  getTreeItem(n: Node): vscode.TreeItem {
    if (n.kind === "surface") {
      const r = this.records[n.i];
      const v = verdictOf(r);
      const t = new vscode.TreeItem(r.surface, vscode.TreeItemCollapsibleState.Expanded);
      t.description = `${v.toLowerCase()} · ${scoreText(r)} · ${r.profile}/${r.level}`;
      t.iconPath = v === "CONFORMANT" ? new vscode.ThemeIcon("pass", PASS)
        : v === "UNSCANNABLE" ? new vscode.ThemeIcon("warning", WARN) : new vscode.ThemeIcon("error", FAIL);
      t.tooltip = `${r.standard} ${r.version}, generated ${r.generated_at ?? "?"}`;
      t.contextValue = "surface";
      return t;
    }
    if (n.kind === "note") {
      const t = new vscode.TreeItem(n.text, vscode.TreeItemCollapsibleState.None);
      t.iconPath = new vscode.ThemeIcon(n.icon, n.color === "warn" ? WARN : n.color === "fail" ? FAIL : undefined);
      t.tooltip = n.text;
      return t;
    }
    if (n.kind === "group") {
      const r = this.records[n.i];
      const count = n.group === "fix" ? (r.fix_queue ?? []).length
        : n.group === "unassessed" ? (r.unassessed ?? []).length : passed(r).length;
      const label = n.group === "fix" ? "Fix queue" : n.group === "unassessed" ? "Could not assess" : "Passed";
      const t = new vscode.TreeItem(`${label} (${count})`,
        count === 0 ? vscode.TreeItemCollapsibleState.None
          : n.group === "passed" ? vscode.TreeItemCollapsibleState.Collapsed : vscode.TreeItemCollapsibleState.Expanded);
      t.iconPath = new vscode.ThemeIcon(n.group === "fix" ? "tools" : n.group === "unassessed" ? "question" : "check-all");
      return t;
    }
    const t = new vscode.TreeItem(`${n.rule}  ${n.title}`, vscode.TreeItemCollapsibleState.None);
    t.description = n.group === "passed" ? undefined : n.severity;
    t.iconPath = n.group === "passed" ? new vscode.ThemeIcon("pass", PASS)
      : n.group === "unassessed" ? new vscode.ThemeIcon("question", WARN) : severityIcon(n.severity);
    const md = new vscode.MarkdownString();
    md.appendMarkdown(`**${n.rule}** ${n.title}\n\n`);
    if (n.tip) md.appendCodeblock(n.tip, "text");
    t.tooltip = md;
    t.contextValue = n.group === "fix" ? "finding" : n.group;
    t.command = { command: "agssh.showRule", title: "Show Rule Text", arguments: [n] };
    return t;
  }
}
