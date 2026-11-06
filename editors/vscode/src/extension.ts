import * as crypto from "crypto";
import * as fs from "fs";
import * as os from "os";
import * as vscode from "vscode";
import { BinaryNotFoundError, ruleText, scanConfig, scanUrl, version } from "./cli";
import { renderReport } from "./html";
import { resolveBinary } from "./locate";
import { ConformanceRecord, fixPrompt, reportPrompt, summary } from "./record";
import { Node, ResultsTree } from "./tree";

type Target = { kind: "url"; url: string } | { kind: "config"; path: string };

let output: vscode.OutputChannel;
let status: vscode.StatusBarItem;
let tree: ResultsTree;
let view: vscode.TreeView<Node>;
let panel: vscode.WebviewPanel | undefined;
let records: ConformanceRecord[] = [];
let target: Target | undefined;
let busy: AbortController | undefined;

function bin(): string {
  const setting = vscode.workspace.getConfiguration("agssh").get<string>("binaryPath");
  return resolveBinary(setting, os.homedir(), process.platform, (p) => fs.existsSync(p));
}

function verifyCommand(): string | undefined {
  if (target?.kind !== "config") return undefined;
  const rel = vscode.workspace.asRelativePath(target.path);
  return `agssh -config ${rel}`;
}

async function notifyError(err: unknown): Promise<void> {
  const msg = err instanceof Error ? err.message : String(err);
  output.appendLine(`error: ${msg}`);
  if (err instanceof BinaryNotFoundError) {
    const pick = await vscode.window.showErrorMessage(
      `agssh: ${msg}. Install it (go install github.com/fabriziosalmi/agssh/cmd/agssh@latest or a release archive) or set agssh.binaryPath.`,
      "Set binary path", "Show output");
    if (pick === "Set binary path") await vscode.commands.executeCommand("workbench.action.openSettings", "agssh.binaryPath");
    if (pick === "Show output") output.show(true);
    return;
  }
  const pick = await vscode.window.showErrorMessage(`agssh: ${msg}`, "Show output");
  if (pick) output.show(true);
}

function setStatus(text: string, tooltip: string, warn = false): void {
  status.text = text;
  status.tooltip = tooltip;
  status.backgroundColor = warn ? new vscode.ThemeColor("statusBarItem.warningBackground") : undefined;
  status.show();
}

function showRecords(recs: ConformanceRecord[]): void {
  records = recs;
  tree.set(recs);
  void vscode.commands.executeCommand("setContext", "agssh.hasScan", recs.length > 0);
  const s = summary(recs);
  const fails = recs.reduce((n, r) => n + (r.fix_queue?.length ?? 0), 0);
  view.badge = fails ? { value: fails, tooltip: `${fails} rule(s) to fix` } : undefined;
  const icon = s.verdict === "CONFORMANT" ? "$(pass)" : s.verdict === "UNSCANNABLE" ? "$(warning)" : "$(error)";
  setStatus(`${icon} agssh ${s.text}`, `AGSSH-STD-001: ${s.verdict.toLowerCase()}. Click to open the report.`,
    s.verdict !== "CONFORMANT");
  if (panel) panel.webview.html = renderReport(recs, nonce());
}

function nonce(): string {
  return crypto.randomBytes(16).toString("base64");
}

async function runScan(t: Target): Promise<void> {
  if (busy) {
    void vscode.window.showWarningMessage("agssh: a scan is already running.");
    return;
  }
  const cfg = vscode.workspace.getConfiguration("agssh");
  const timeout = Math.max(5, cfg.get<number>("timeoutSeconds") ?? 45);
  const b = bin();
  const label = t.kind === "url" ? t.url : vscode.workspace.asRelativePath(t.path);
  busy = new AbortController();
  setStatus("$(sync~spin) agssh scanning", `Scanning ${label}`);
  output.appendLine(`scan ${label} with ${b}`);
  try {
    const res = await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: `agssh: scanning ${label}`, cancellable: true },
      (_p, token) => {
        token.onCancellationRequested(() => busy?.abort());
        return t.kind === "url"
          ? scanUrl(b, t.url, cfg.get<string>("profile") ?? "Bronze", cfg.get<string>("level") ?? "L0", timeout, busy!.signal)
          : scanConfig(b, t.path, timeout, busy!.signal);
      });
    target = t;
    if (res.log.trim()) output.appendLine(res.log.trimEnd());
    showRecords(res.records);
    const s = summary(res.records);
    const pick = await vscode.window.showInformationMessage(`agssh: ${label} is ${s.verdict.toLowerCase()} (${s.text}).`, "Open report");
    if (pick) openReport();
  } catch (err) {
    if (records.length) showRecords(records); else setStatus("$(shield) agssh", "No scan yet");
    await notifyError(err);
  } finally {
    busy = undefined;
  }
}

async function scanUrlCommand(ctx: vscode.ExtensionContext): Promise<void> {
  const last = ctx.workspaceState.get<string>("agssh.lastUrl") ?? "https://";
  const url = await vscode.window.showInputBox({
    title: "agssh: scan a live URL",
    prompt: "The deployed surface to check against AGSSH-STD-001",
    value: last,
    validateInput: (v) => (/^https?:\/\/[^\s/]+/i.test(v.trim()) ? undefined : "Enter an http(s) URL"),
  });
  if (!url) return;
  await ctx.workspaceState.update("agssh.lastUrl", url.trim());
  await runScan({ kind: "url", url: url.trim() });
}

async function scanConfigCommand(): Promise<void> {
  const files = await vscode.workspace.findFiles("**/.airgap.yml", "**/node_modules/**", 50);
  if (!files.length) {
    void vscode.window.showWarningMessage("agssh: no .airgap.yml in this workspace.");
    return;
  }
  let file = files[0];
  if (files.length > 1) {
    const pick = await vscode.window.showQuickPick(
      files.map((f) => ({ label: vscode.workspace.asRelativePath(f), f })), { title: "agssh: which manifest?" });
    if (!pick) return;
    file = pick.f;
  }
  await runScan({ kind: "config", path: file.fsPath });
}

function openReport(): void {
  if (!records.length) return;
  if (panel) {
    panel.reveal();
    return;
  }
  panel = vscode.window.createWebviewPanel("agssh.report", "agssh report", vscode.ViewColumn.Active,
    { enableScripts: true, retainContextWhenHidden: true, localResourceRoots: [] });
  panel.onDidDispose(() => { panel = undefined; });
  panel.webview.onDidReceiveMessage(async (m: { act: string; surface: number; rule: string }) => {
    if (m.act === "copyFix") await copyFix(m.surface, m.rule);
    else if (m.act === "showRule") await showRule(m.rule);
    else if (m.act === "copyReport") await copyReport();
    else if (m.act === "rescan" && target) await runScan(target);
  });
  panel.webview.html = renderReport(records, nonce());
}

async function copyFix(i: number, rule: string): Promise<void> {
  const r = records[i];
  if (!r || !/^AG-[A-Z]+-[0-9]+[a-z]?$/.test(rule)) return;
  try {
    const text = fixPrompt(r, rule, await ruleText(bin(), rule), verifyCommand());
    await vscode.env.clipboard.writeText(text);
    void vscode.window.showInformationMessage(`agssh: fix prompt for ${rule} copied. Paste it into Copilot Chat or Claude.`);
  } catch (err) {
    await notifyError(err);
  }
}

async function copyReport(): Promise<void> {
  if (!records.length) return;
  await vscode.env.clipboard.writeText(reportPrompt(records, verifyCommand()));
  void vscode.window.showInformationMessage("agssh: fix prompt for the whole report copied.");
}

async function showRule(rule: string): Promise<void> {
  if (!/^AG-[A-Z]+-[0-9]+[a-z]?$/.test(rule)) return;
  try {
    const doc = await vscode.workspace.openTextDocument({ language: "markdown", content: await ruleText(bin(), rule) });
    await vscode.commands.executeCommand("markdown.showPreviewToSide", doc.uri);
  } catch (err) {
    await notifyError(err);
  }
}

export function activate(ctx: vscode.ExtensionContext): void {
  output = vscode.window.createOutputChannel("agssh");
  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  status.command = "agssh.openReportOrFocus";
  tree = new ResultsTree();
  view = vscode.window.createTreeView("agssh.results", { treeDataProvider: tree, showCollapseAll: true });
  setStatus("$(shield) agssh", "No scan yet. Click to open the agssh view.");

  const b = bin();
  version(b).then((v) => output.appendLine(`using ${b}: ${v}`), (e: unknown) => output.appendLine(`agssh not usable at ${b}: ${String(e)}`));

  ctx.subscriptions.push(output, status, view,
    vscode.commands.registerCommand("agssh.scanUrl", () => scanUrlCommand(ctx)),
    vscode.commands.registerCommand("agssh.scanConfig", scanConfigCommand),
    vscode.commands.registerCommand("agssh.rescan", () => (target ? runScan(target) : undefined)),
    vscode.commands.registerCommand("agssh.openReport", openReport),
    vscode.commands.registerCommand("agssh.openReportOrFocus", () =>
      records.length ? openReport() : vscode.commands.executeCommand("agssh.results.focus")),
    vscode.commands.registerCommand("agssh.copyReportPrompt", copyReport),
    vscode.commands.registerCommand("agssh.copyFixPrompt", (n?: Node) => (n?.kind === "item" ? copyFix(n.i, n.rule) : undefined)),
    vscode.commands.registerCommand("agssh.showRule", (n?: Node | string) =>
      showRule(typeof n === "string" ? n : n?.kind === "item" ? n.rule : "")),
    vscode.commands.registerCommand("agssh.showOutput", () => output.show(true)),
  );
}

export function deactivate(): void {
  busy?.abort();
}
